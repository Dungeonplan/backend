package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/Dungeonplan/backend/security"
	"golang.org/x/oauth2"
)

type DiscordLoginResponse struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Avatar   string `json:"avatar"`
	Locale   string `json:"locale"`
	EMail    string `json:"email"`
	//Verified bool   `json:"verified"`
	//AvatarDecoration string `json:"avatar_decoration"`
	//Discriminator    string `json:"discriminator"`
	//PublicFlags      int    `json:"public_flags"`
	//Flags            int    `json:"flags"`
	//Banner           string `json:"banner"`
	//BannerColor      string `json:"banner_color"`
	//AccentColor      int    `json:"accent_color"`
	//MFAEnabled       bool   `json:"mfa_eabled"`
}

func (env *Env) handleLoginDiscord(w http.ResponseWriter, r *http.Request) {
	state, err := security.GenerateRandomString(32)
	checkErr(err)

	stmt, err := env.database.Prepare("INSERT INTO oauth2_state(sso_service, state, timestamp) VALUES (?, ?, ?);")
	checkErr(err)

	stmt.Exec(sso_service_discord, state, time.Now().Unix())
	checkErr(err)

	var url string
	if env.environment == "dev" {
		url = discordOAuthConfigDev.AuthCodeURL(state)
	} else {
		url = discordOAuthConfigProd.AuthCodeURL(state)
	}

	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func (env *Env) handleLoginDiscordCallback(w http.ResponseWriter, r *http.Request) {
	state := r.FormValue("state")
	code := r.FormValue("code")
	rows, err := env.database.Query("SELECT COUNT(*) FROM oauth2_state WHERE state = ?", state)
	checkErr(err)

	if checkRowsCount(rows) == 1 {
		stmt, err := env.database.Prepare("DELETE FROM oauth2_state WHERE state = ?")
		checkErr(err)
		_, err = stmt.Exec(state)
		checkErr(err)

		var token *oauth2.Token

		if env.environment == "dev" {
			token, err = discordOAuthConfigDev.Exchange(oauth2.NoContext, code)
		} else {
			token, err = discordOAuthConfigProd.Exchange(oauth2.NoContext, code)
		}
		checkErr(err)

		client := &http.Client{}
		request, err := http.NewRequest("GET", "https://discord.com/api/users/@me", nil)
		checkErr(err)

		request.Header.Set("Authorization", "Bearer "+token.AccessToken)
		response, err := client.Do(request)
		checkErr(err)

		defer response.Body.Close()

		body, err := ioutil.ReadAll(response.Body)
		var result DiscordLoginResponse
		if err := json.Unmarshal(body, &result); err != nil {
			panic("Could not parse answer from Discord API: " + err.Error())
		}

		rows, err = env.database.Query("SELECT COUNT(*) FROM user WHERE email = ?", result.EMail)
		checkErr(err)

		if checkRowsCount(rows) == 1 {
			//TODO: User exists
			fmt.Fprintf(w, "User was successfully logged in.")
		} else {
			stmt, err := env.database.Prepare("INSERT INTO user(email, username, discordid, discordavatar, locale) VALUES (?, ?, ?, ?, ?);")
			checkErr(err)
			stmt.Exec(result.EMail, result.Username, result.ID, result.Avatar, result.Locale)
			checkErr(err)
			//TODO: Finish registration
			fmt.Fprintf(w, "User was successfully registered.")
		}

	} else {
		http.Redirect(w, r, errorPageURL, http.StatusTemporaryRedirect)
	}
}
