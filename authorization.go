package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"time"

	"github.com/Dungeonplan/backend/security"
	"github.com/dgrijalva/jwt-go"
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
	// Accept only GET
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	state, err := security.GenerateRandomString(32)
	checkErr(err)

	stmt, err := env.database.Prepare("INSERT INTO oauth2_state(sso_service, state, timestamp) VALUES (?, ?, ?);")
	checkErr(err)

	_, err = stmt.Exec(sso_service_discord, state, time.Now().Unix())
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
	// Accept only GET
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
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
		checkErr(err)

		var result DiscordLoginResponse
		if err := json.Unmarshal(body, &result); err != nil {
			panic("Could not parse answer from Discord API: " + err.Error())
		}

		rows, err = env.database.Query("SELECT COUNT(*) FROM user WHERE email = ?", result.EMail)
		checkErr(err)

		var userID int64 = -1

		if checkRowsCount(rows) == 0 {
			stmt, err := env.database.Prepare("INSERT INTO user(email, username, discordid, discordavatar, locale) VALUES (?, ?, ?, ?, ?);")
			checkErr(err)
			result, err := stmt.Exec(result.EMail, result.Username, result.ID, result.Avatar, result.Locale)
			checkErr(err)
			userID, err = result.LastInsertId()
			checkErr(err)
		} else {
			rows, err := env.database.Query("SELECT id FROM user WHERE email = ?", result.EMail)
			checkErr(err)
			for rows.Next() {
				err := rows.Scan(&userID)
				checkErr(err)
			}
		}
		stmt, err = env.database.Prepare("INSERT INTO authorize_token(token, user_id, expiry) VALUES (?, ?, ?);")
		checkErr(err)
		auth_token, err := security.GenerateRandomString(32)
		checkErr(err)

		// If user could not be added, for some reason. Should not happen
		if userID == -1 {
			http.Redirect(w, r, errorPageURL, http.StatusTemporaryRedirect)
			return
		}

		_, err = stmt.Exec(auth_token, userID, time.Now().Add(time.Minute*time.Duration(60)).Unix())
		checkErr(err)
		http.Redirect(w, r, authorizeURL+auth_token, http.StatusTemporaryRedirect)
	} else {
		http.Redirect(w, r, errorPageURL, http.StatusTemporaryRedirect)
	}
}

type TokenExchangeResponse struct {
	Token string `json:"token"`
}

func (env *Env) tokenExchange(w http.ResponseWriter, r *http.Request) {
	//Accept only POST
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var resp TokenExchangeResponse

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	err := decoder.Decode(&resp)

	if err != nil || resp.Token == "" {
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
		} else {
			http.Error(w, "json: field token is empty", http.StatusBadRequest)
		}
		return
	}

	rows, err := env.database.Query("SELECT COUNT(*) FROM authorize_token WHERE token = ?", resp.Token)
	checkErr(err)
	rows_count := checkRowsCount(rows)

	// Return 401 if Token was not found
	if rows_count == 0 {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	var tokenid int
	var userid int
	var used bool
	var expiry int

	row := env.database.QueryRow("SELECT id, user_id, used, expiry FROM authorize_token WHERE token = ?", resp.Token)
	err = row.Scan(&tokenid, &userid, &used, &expiry)
	checkErr(err)

	// Return 401 if Token was expired
	if expiry < int(time.Now().Unix()) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// Return 401 if Token was used multiple times and invalidate jwt token
	if used {
		stmt, err := env.database.Prepare("UPDATE jwt_token SET valid = 0 WHERE authorize_token_id = ?")
		checkErr(err)
		_, err = stmt.Exec(tokenid)
		checkErr(err)

		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	type Claims struct {
		UserID int `json:"userid"`
		jwt.StandardClaims
	}

	// Create new JWT Token
	claims := &Claims{
		UserID: userid,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Second * time.Duration(jwt_expiry)).Unix(),
			IssuedAt:  time.Now().Unix(),
		},
	}

	jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	jwtTokenString, err := jwtToken.SignedString([]byte(os.Getenv("DUNGEONPLAN_PRESHARED_KEY")))

	// Return 500 if something went wrong during token creation
	if err != nil {
		fmt.Println(err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Add JWT Token to database
	stmt, err := env.database.Prepare("INSERT INTO jwt_token(user_id, authorize_token_id, jwt_token) VALUES (?, ?, ?);")
	checkErr(err)
	_, err = stmt.Exec(userid, tokenid, jwtTokenString)
	checkErr(err)

	// Set used to true for authorize_token
	stmt, err = env.database.Prepare("UPDATE authorize_token SET used = 1 WHERE id = ?")
	checkErr(err)
	_, err = stmt.Exec(tokenid)
	checkErr(err)

	//Return JWT Token
	type JWTResponse struct {
		Token string `json:"token"`
	}

	body := JWTResponse{Token: jwtTokenString}

	json, err := json.Marshal(body)
	checkErr(err)
	w.Header().Set("Content-Type", "application/json")
	w.Write(json)
}
