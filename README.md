# apple-user-transfer

Migrate existing Sign in with Apple user identifiers and private email relay addresses by exchanging transfer identifiers from one developer team to another with the user migration info endpoint.

Please follow the following steps to process the user migration from your team (Team A) to the recipient team (Team B):

** Transferring existing users to a recipient team **
1. Team A obtains access token(s)
2. Team A generates transfer identifers
3. Team A initiates app transfer to Team B

** Bringing users from the transferring team into your team **
4. Team B obtains access token(s)
5. Team B exchanges transfer identifers
6. Team B confirms successful user migration
