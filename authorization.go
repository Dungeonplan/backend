package main

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"os"
	"time"

	"github.com/Dungeonplan/backend/security"
	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/oauth2"
)

type DiscordLoginResponse struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Avatar   string `json:"avatar"`
	Locale   string `json:"locale"`
	EMail    string `json:"email"`
}

type TokenExchangeResponse struct {
	Token string `json:"token"`
}

type Claims struct {
	UserID int `json:"userid"`
	jwt.RegisteredClaims
}

func (env *Env) authorized(w http.ResponseWriter, r *http.Request) bool {
	jwtToken := extractBearerToken(r.Header.Get("Authorization"))

	// Return 401 if no Token was submitted
	if jwtToken == "" {
		w.WriteHeader(http.StatusUnauthorized)
		return false
	}

	claims := &Claims{}

	token, err := jwt.ParseWithClaims(jwtToken, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("DUNGEONPLAN_PRESHARED_KEY")), nil
	})

	if err != nil {
		// Return 401 if signature is invalid, expired, etc.
		w.WriteHeader(http.StatusUnauthorized)
		return false
	}

	// Return 401 if token was invalidated before
	if !token.Valid || env.wasTokenInvalidated(jwtToken) {
		w.WriteHeader(http.StatusUnauthorized)
		return false
	}

	return true
}

func (env *Env) wasTokenInvalidated(token string) bool {
	var valid bool
	row := env.database.QueryRow("SELECT valid FROM jwt_token WHERE jwt_token = ?", token)
	checkErr(row.Scan(&valid))
	return !valid
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
			token, err = discordOAuthConfigDev.Exchange(context.Background(), code)
		} else {
			token, err = discordOAuthConfigProd.Exchange(context.Background(), code)
		}
		checkErr(err)

		client := &http.Client{}
		request, err := http.NewRequest("GET", "https://discord.com/api/users/@me", nil)
		checkErr(err)

		request.Header.Set("Authorization", "Bearer "+token.AccessToken)
		response, err := client.Do(request)
		checkErr(err)

		defer func() {
			err = response.Body.Close()
		}()
		checkErr(err)

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
			rowsUser, err := env.database.Query("SELECT id FROM user")
			checkErr(err)

			var role int
			if checkRowsCount(rowsUser) == 0 {
				role = systemrole_admin
			} else {
				role = systemrole_user
			}

			stmt, err := env.database.Prepare("INSERT INTO user(email, username, discordid, discordavatar, locale, role) VALUES (?, ?, ?, ?, ?, ?);")
			checkErr(err)
			result, err := stmt.Exec(result.EMail, result.Username, result.ID, result.Avatar, result.Locale, role)
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
		authToken, err := security.GenerateRandomString(32)
		checkErr(err)

		// If user could not be added, for some reason. Should not happen
		if userID == -1 {
			http.Redirect(w, r, errorPageURL, http.StatusTemporaryRedirect)
			return
		}

		_, err = stmt.Exec(authToken, userID, time.Now().Add(time.Minute*time.Duration(60)).Unix())
		checkErr(err)
		http.Redirect(w, r, authorizeURL+authToken, http.StatusTemporaryRedirect)
	} else {
		http.Redirect(w, r, errorPageURL, http.StatusTemporaryRedirect)
	}
}

func (env *Env) handleTokenExchange(w http.ResponseWriter, r *http.Request) {
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
	rowsCount := checkRowsCount(rows)

	// Return 401 if Token was not found
	if rowsCount == 0 {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	var tokenID int
	var userid int
	var used bool
	var expiry int

	row := env.database.QueryRow("SELECT id, user_id, used, expiry FROM authorize_token WHERE token = ?", resp.Token)
	err = row.Scan(&tokenID, &userid, &used, &expiry)
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
		_, err = stmt.Exec(tokenID)
		checkErr(err)

		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// Create new JWT Token
	claims := &Claims{
		UserID: userid,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Second * time.Duration(jwt_expiry))),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	jwtTokenString, err := jwtToken.SignedString([]byte(os.Getenv("DUNGEONPLAN_PRESHARED_KEY")))

	// Return 500 if something went wrong during token creation
	if err != nil {
		log("Error: " + err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Add JWT Token to database
	stmt, err := env.database.Prepare("INSERT INTO jwt_token(user_id, authorize_token_id, jwt_token) VALUES (?, ?, ?);")
	checkErr(err)
	_, err = stmt.Exec(userid, tokenID, jwtTokenString)
	checkErr(err)

	// Set used to true for authorize_token
	stmt, err = env.database.Prepare("UPDATE authorize_token SET used = 1 WHERE id = ?")
	checkErr(err)
	_, err = stmt.Exec(tokenID)
	checkErr(err)

	//Return JWT Token
	type JWTResponse struct {
		Token string `json:"token"`
	}

	body := JWTResponse{Token: jwtTokenString}

	jsn, err := json.Marshal(body)
	checkErr(err)
	w.Header().Set("Content-Type", "application/json")
	_, err = w.Write(jsn)
	checkErr(err)
}

func (env *Env) handleLogout(w http.ResponseWriter, r *http.Request) {
	// Accept only GET
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	// Return 401 if user is not authorized
	if !env.authorized(w, r) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	jwtToken := extractBearerToken(r.Header.Get("Authorization"))
	stmt, err := env.database.Prepare("UPDATE jwt_token SET valid = 0 WHERE jwt_token = ?")
	checkErr(err)
	_, err = stmt.Exec(jwtToken)
	checkErr(err)

	body := SuccessResponse{Success: true, Description: "Logout successful."}
	jsn, err := json.Marshal(body)
	checkErr(err)
	w.Header().Set("Content-Type", "application/json")
	_, err = w.Write(jsn)
	checkErr(err)
}
