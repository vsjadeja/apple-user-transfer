package main

import (
	"bytes"
	"crypto/x509"
	"database/sql"
	_ "embed"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	_ "github.com/lib/pq"
	l "github.com/mvmnt-fit/fitos-core/logger"
)

var db *sql.DB
var err error
var logger l.LoggerInterface
var logFile *os.File

//go:embed newkey.p8
var newKeyData string

func main() {
	defer logFile.Close()
	defer db.Close()

	newClientSecret, err := generateClientSecret(NewTeamID, NewKeyID, newKeyData, NewClientID)
	if err != nil {
		fmt.Println("error while generating new client secrete", NewTeamID, NewKeyID, NewClientID, "error:", err)
		panic(err)
	}

	newAccessToken, err := getAppleApiAccessToken(NewClientID, newClientSecret)
	if err != nil {
		fmt.Println("error while getting new access token", NewClientID, newClientSecret, "error:", err)
		panic(err)
	}
	userTransferIds := getUserTransferIdFromDB()
	for fpUserId, userTransferId := range userTransferIds {
		userInfo, err := getUserInfoByTransferID(NewClientID, newClientSecret, newAccessToken, userTransferId)
		if err != nil {
			fmt.Println("Error:", err)
			continue
		}

		fmt.Println(userTransferId, userInfo.Sub, userInfo.Email, userInfo.IsPrivateEmail)

		// Update your user info in database with the new information.
		// When user enables private email for Apple Sign-in, the email is also different after transfer.
		if userInfo.IsPrivateEmail {
			err := updateUser(fpUserId, userInfo.Email)
			if err != nil {
				fmt.Println("Update record error:", err, fpUserId, userInfo.Email, userInfo.Sub)
			}
		}

		err = markTransfered(fpUserId)
		if err != nil {
			fmt.Println("Update mark transfered error:", err, fpUserId, userInfo.Sub)
		}
	}

}

func getUserTransferIdFromDB() map[int64]string {
	var users = make(map[int64]string)

	rows, err := db.Query(`SELECT id,apple_transfer_id FROM auth_user WHERE apple_transfer_id is not null and is_apple_user_migrated is null`)
	if err == nil {
		for rows.Next() {
			var id int64
			var sub string
			e := rows.Scan(&id, &sub)
			if e == nil && sub != "" {
				users[id] = sub
			}
		}
	} else {
		logFile.WriteString(`Read AuthUser ERROR:` + err.Error() + "\n")
	}

	defer rows.Close()

	return users
}

// Update user info in database with the new email
// When user enables private email for Apple Sign-in, the email is also different after transfer.
func updateUser(fpUserId int64, email string) error {
	updateQuery := fmt.Sprintf(`UPDATE auth_user SET email = '%s', username = '%s' WHERE id=%d`, email, email, fpUserId)
	result, err := db.Exec(updateQuery)
	if err != nil {
		logFile.WriteString(fmt.Sprintf(`could not execute update query: %v`, err) + "\n")
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		logFile.WriteString(fmt.Sprintf(`could not fetch rows affected: %v`, err) + "\n")
	} else {
		logFile.WriteString(fmt.Sprintf(`Record updated for ID:%d with email=%s Affected row:%d`, fpUserId, email, rowsAffected) + "\n")
	}

	return err
}

func markTransfered(fpUserId int64) error {
	updateQuery := fmt.Sprintf(`UPDATE auth_user SET is_apple_user_migrated = %v WHERE id=%d`, true, fpUserId)
	result, err := db.Exec(updateQuery)
	if err != nil {
		logFile.WriteString(fmt.Sprintf(`could not execute update query: %v`, err) + "\n")
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		logFile.WriteString(fmt.Sprintf(`could not fetch rows affected: %v`, err) + "\n")
	} else {
		logFile.WriteString(fmt.Sprintf(`Record updated for ID:%d Affected row:%d`, fpUserId, rowsAffected) + "\n")
	}

	return err
}

func getAppleApiAccessToken(clientID, clientSecret string) (string, error) {
	// Prepare form data
	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("scope", "user.migration")
	data.Set("client_id", clientID)
	data.Set("client_secret", clientSecret)

	// Create the HTTP request
	req, err := http.NewRequest("POST", AuthTokenURL, bytes.NewBufferString(data.Encode()))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %v", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Send the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to make request: %v", err)
	}
	defer resp.Body.Close()

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %v", err)
	}

	// Check for non-200 status codes
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("received non-200 response: %d, body: %s", resp.StatusCode, string(body))
	}

	// Parse the response to extract the access token
	type AppleTokenResponse struct {
		AccessToken string `json:"access_token"`
	}

	var tokenResponse AppleTokenResponse
	if err := json.Unmarshal(body, &tokenResponse); err != nil {
		return "", fmt.Errorf("failed to parse JSON response: %v", err)
	}

	return tokenResponse.AccessToken, nil
}

func generateClientSecret(teamID, keyID, encKey, clientID string) (string, error) {
	// Read the private key file

	keyData := []byte(encKey)

	// Parse the private key
	block, _ := pem.Decode(keyData)
	if block == nil || block.Type != "PRIVATE KEY" {
		return "", fmt.Errorf("failed to decode PEM block containing private key")
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse private key: %v", err)
	}

	// Define the claims
	claims := jwt.MapClaims{
		"iss": teamID,                                     // Issuer
		"aud": "https://appleid.apple.com",                // Audience
		"sub": clientID,                                   // Subject
		"exp": time.Now().Add(30 * 24 * time.Hour).Unix(), // Expiration (30 days)
	}

	// Create the JWT token
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)

	// Set the key ID header
	token.Header["kid"] = keyID

	// Sign the token with the private key
	clientSecret, err := token.SignedString(privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign JWT: %v", err)
	}

	return clientSecret, nil
}

// UserInfo represents the structure of the user info returned by Apple
type UserInfo struct {
	Sub            string `json:"sub"`
	Email          string `json:"email"`
	IsPrivateEmail bool   `json:"is_private_email"`
}

// getUserInfoByTransferID sends a POST request to fetch user information by transfer ID
func getUserInfoByTransferID(clientID, clientSecret, accessToken, appleTransferID string) (*UserInfo, error) {
	// Prepare form data
	data := url.Values{}
	data.Set("transfer_sub", appleTransferID)
	data.Set("client_id", clientID)
	data.Set("client_secret", clientSecret)

	// Create the HTTP request
	req, err := http.NewRequest("POST", UserMigrationInfoURL, bytes.NewBufferString(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+accessToken)

	// Send the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %v", err)
	}
	defer resp.Body.Close()

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}

	// Check for non-200 status codes
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("received non-200 response: %d, body: %s", resp.StatusCode, string(body))
	}

	// Parse the response JSON into UserInfo struct
	var userInfo UserInfo
	if err := json.Unmarshal(body, &userInfo); err != nil {
		return nil, fmt.Errorf("failed to parse JSON response: %v", err)
	}

	return &userInfo, nil
}

func init() {
	// initialize logger
	logger = l.NewJSONInfoLogger(os.Stdout, "", 0)

	// Customize the usage function
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "This script facilitates the migration of user accounts authenticated via Apple Sign-In.\nIt ensures user data integrity while securely transferring credentials and profile information.\n\n")
		fmt.Fprintf(os.Stderr, "It comprises the following four steps:\n\n")
		fmt.Fprintf(os.Stderr, "1: Generate recieverTeam's client secret.\n")
		fmt.Fprintf(os.Stderr, "2: Get recieverTeam's access token.\n")
		fmt.Fprintf(os.Stderr, "3: Transfer the apple sign-in users.\n")
		fmt.Fprintf(os.Stderr, "4: Update application database for updated email.\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nFor additional help, please contact \033[32mVirendra Jadeja\033[0m <\033[34mvirendrajadeja84@gmail.com\033[0m>\n")
	}

	flag.Parse()

	// Create error file to log error
	logFile, err = os.Create(fmt.Sprintf(`./user-migration-log-%d.txt`, time.Now().Unix()))
	if err != nil {
		log.Fatalf("failed creating log file: %s", err)
	} else {
		logger.Log(l.Info, l.Fields{`Log File: `: logFile.Name()})
	}

	if logFile != nil {
		currentTime := time.Now()
		logFile.WriteString(fmt.Sprintf(`Date: %s`, currentTime.String()) + "\n")
	}
	// Connect to database
	conn := fmt.Sprintf("user=%s password=%s dbname=%s host=%s port=%s sslmode=disable", DBUsername, DBPassword, DBDatabase, DBHost, DBPort)
	db, err = sql.Open("postgres", conn)
	if err != nil {
		log.Fatalf(`fail to connect with production database: %s`, err)
		logFile.WriteString(`Fail to connect with production database.` + "\n")
	} else {
		logger.Log(l.Info, l.Fields{`Production DB:`: ` Connected.`})
		logFile.WriteString(`Connected to production database.` + "\n")
	}
}
