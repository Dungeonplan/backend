package main

import (
	"os"

	"golang.org/x/oauth2"
)

const (
	baseURL      = "https://test.dungeonplan.de"
	errorPageURL = baseURL + "/error"
	authorizeURL = baseURL + "/authorize?token="
)

const (
	exchange_token_expiry = 60   // Seconds
	jwt_expiry            = 3600 // Seconds
)

const (
	dungeonplan_version = "0.1"
	systemrole_admin    = 1
	systemrole_user     = 2
)

const (
	sso_service_discord = 1
)

var (
	discordOAuthConfigDev = &oauth2.Config{
		RedirectURL:  "http://localhost:8123/api/logindiscordcallback",
		ClientID:     os.Getenv("DUNGEONPLAN_DISCORD_CLIENT_ID"),
		ClientSecret: os.Getenv("DUNGEONPLAN_DISCORD_CLIENT_SECRET"),
		Scopes:       []string{"email"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://discord.com/api/oauth2/authorize",
			TokenURL: "https://discord.com/api/oauth2/token",
		},
	}
	discordOAuthConfigProd = &oauth2.Config{
		RedirectURL:  baseURL + "/api/logindiscordcallback",
		ClientID:     os.Getenv("DUNGEONPLAN_DISCORD_CLIENT_ID"),
		ClientSecret: os.Getenv("DUNGEONPLAN_DISCORD_CLIENT_SECRET"),
		Scopes:       []string{"email"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://discord.com/api/oauth2/authorize",
			TokenURL: "https://discord.com/api/oauth2/token",
		},
	}
)
