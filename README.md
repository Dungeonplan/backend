# Dungeonplan Backend 
This is the backend for Dungeonplan, written in GoLang.
## Prerequisites for Running
- Go v1.18+
- SSO Service (currently just Discord is supported)
  - Register a new application at https://discord.com/developers/applications
- Environment variables
  - DUNGEONPLAN_DISCORD_CLIENT_ID - Discord Client ID for registered Application
  - DUNGEONPLAN_DISCORD_CLIENT_SECRET- Discord Client Secret for registered Application
  - DUNGEONPLAN_PRESHARED_KEY - A random string with at least 128 characters for JWT creation
  - DUNGEONPLAN_ENV - "dev" or "prod", to switch between configs (see config.go)
## Running / Building
- Clone Repository
- Download dependencies
  - go get github.com/golang-jwt/jwt/v4
  - go get golang.org/x/oauth2
  - go get github.com/gorilla/mux
- go build *.go
- (Optional) ./backend
## How to contribute
- Fork Repository
- Develop your Features
- Create a Pull Request