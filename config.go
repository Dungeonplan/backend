package main

import (
	"os"

	"golang.org/x/oauth2"
)

const (
	baseURLDev   = "http://localhost:4200"
	baseURLProd  = "https://test.dungeonplan.de"
	errorPageURL = "/error"
	authorizeURL = "/authorize/"
)

const (
	exchange_token_expiry = 60 // Seconds
	// TODO: Reduce to 1 hour
	jwt_expiry = 3600 * 24 // Seconds
)

const (
	dungeonplan_version = "0.1"
	dungeonplan_build   = 4
	systemrole_admin    = 1
	systemrole_user     = 2
)

const (
	sso_service_discord = 1
)

const (
	action_role_add    = "role_add"
	action_role_delete = "role_delete"
	action_role_update = "role_modify"
)

var (
	discordOAuthConfigDev = &oauth2.Config{
		RedirectURL:  "http://localhost:8123/api/logindiscordcallback",
		ClientID:     os.Getenv("DUNGEONPLAN_DISCORD_CLIENT_ID"),
		ClientSecret: os.Getenv("DUNGEONPLAN_DISCORD_CLIENT_SECRET"),
		Scopes:       []string{"identify", "email"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://discord.com/api/oauth2/authorize",
			TokenURL: "https://discord.com/api/oauth2/token",
		},
	}
	discordOAuthConfigProd = &oauth2.Config{
		RedirectURL:  baseURLProd + "/api/logindiscordcallback",
		ClientID:     os.Getenv("DUNGEONPLAN_DISCORD_CLIENT_ID"),
		ClientSecret: os.Getenv("DUNGEONPLAN_DISCORD_CLIENT_SECRET"),
		Scopes:       []string{"identify", "email"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://discord.com/api/oauth2/authorize",
			TokenURL: "https://discord.com/api/oauth2/token",
		},
	}
)
