package main

import (
	"fmt"
	"net/http"

	"github.com/Dungeonplan/backend/security"
)

func init() {
	security.AssertAvailablePRNG()
}

func main() {
	http.HandleFunc("/login", handleLogin)
	http.ListenAndServe(":8080", nil)
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	state, err := security.GenerateRandomString(32)
	fmt.Println(state)

	if err != nil {
		http.Redirect(w, r, errorPageURL, http.StatusTemporaryRedirect)
	}

	url := discordOAuthCOnfig.AuthCodeURL(state)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}
