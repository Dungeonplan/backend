package main

import (
	"os"

	"golang.org/x/oauth2"
)

const (
	errorPageURL = "http://test.dungeonplan.de/error"
)

var (
	discordOAuthCOnfig = &oauth2.Config{
		RedirectURL:  "http://localhost:1234",
		ClientID:     os.Getenv("DUNGEONPLAN_DISCORD_CLIENT_ID"),
		ClientSecret: os.Getenv("DUNGEONPLAN_DISCORD_CLIENT_SECRET"),
		Scopes:       []string{"email", "identify"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://discord.com/api/oauth2/authorize",
			TokenURL: "https://discord.com/api/oauth2/token",
		},
	}
)
