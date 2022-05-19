package main

import (
	"os"

	"golang.org/x/oauth2"
)

const (
	baseURL      = "http://test.dungeonplan.de"
	errorPageURL = baseURL + "/error"
)

var (
	discordOAuthConfigDev = &oauth2.Config{
		RedirectURL:  "http://localhost:8123/logindiscordcallback",
		ClientID:     os.Getenv("DUNGEONPLAN_DISCORD_CLIENT_ID"),
		ClientSecret: os.Getenv("DUNGEONPLAN_DISCORD_CLIENT_SECRET"),
		Scopes:       []string{"email", "identify"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://discord.com/api/oauth2/authorize",
			TokenURL: "https://discord.com/api/oauth2/token",
		},
	}
	discordOAuthConfigProd = &oauth2.Config{
		RedirectURL:  baseURL + "logindiscordcallback",
		ClientID:     os.Getenv("DUNGEONPLAN_DISCORD_CLIENT_ID"),
		ClientSecret: os.Getenv("DUNGEONPLAN_DISCORD_CLIENT_SECRET"),
		Scopes:       []string{"email", "identify"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://discord.com/api/oauth2/authorize",
			TokenURL: "https://discord.com/api/oauth2/token",
		},
	}
)

const (
	sso_service_discord = 1
)
