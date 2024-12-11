GOBUILDFLAGS=GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o 

.PHONY: clean
clean:
	@echo cleanup complete!
	@rm -rf ./before-app-migration/build
	@rm -rf ./after-app-migration/build

.PHONY: build
build: clean
	@mkdir -p ./before-app-migration/build
	@mkdir -p ./after-app-migration/build
	@echo Compiling...
	@cd ./before-app-migration; go mod tidy
	@cd ./after-app-migration; go mod tidy
	@cd ./before-app-migration; ${GOBUILDFLAGS} ./build/apple-user-migration-tool-phase-1
	@cd ./after-app-migration; ${GOBUILDFLAGS} ./build/apple-user-migration-tool-phase-2
	@echo build complete!

.PHONY: run-after-app-migration
run-after-app-migration: build
	@./after-app-migration/build/apple-user-migration-tool-phase-2

.PHONY: run-before-app-migration
run-before-app-migration: build
	@./before-app-migration/build/apple-user-migration-tool-phase-1