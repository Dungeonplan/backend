package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/Dungeonplan/backend/security"
	_ "github.com/mattn/go-sqlite3"
)

type Env struct {
	database *sql.DB
}

func init() {
	security.AssertAvailablePRNG()
}

func main() {

	db, err := sql.Open("sqlite3", "./database.sqlite")
	checkErr(err)

	env := &Env{database: db}

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		for sig := range c {
			fmt.Println(sig.String())
			db.Close()
			// Code sig c
			os.Exit(130)
		}
	}()

	http.HandleFunc("/logindiscord", env.handleLoginDiscord)
	http.HandleFunc("/logindiscordcallback", env.handleLoginDiscordCallback)
	http.ListenAndServe(":8123", nil)
}

func (env *Env) handleLoginDiscord(w http.ResponseWriter, r *http.Request) {
	state, err := security.GenerateRandomString(32)
	checkErr(err)

	stmt, err := env.database.Prepare("INSERT INTO auth_in_progress(sso_service, state, timestamp) VALUES (?, ?, ?);")
	checkErr(err)

	stmt.Exec(sso_service_discord, state, time.Now().Unix())
	checkErr(err)

	if err != nil {
		http.Redirect(w, r, errorPageURL, http.StatusTemporaryRedirect)
	}

	url := discordOAuthConfigDev.AuthCodeURL(state)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func (env *Env) handleLoginDiscordCallback(w http.ResponseWriter, r *http.Request) {
	state := r.FormValue("state")
	rows, err := env.database.Query("SELECT COUNT(*) FROM auth_in_progress WHERE state = ?", state)
	checkErr(err)

	if checkCount(rows) == 1 {
		stmt, err := env.database.Prepare("DELETE FROM auth_in_progress WHERE state = ?")
		checkErr(err)
		_, err = stmt.Exec(state)
		checkErr(err)
	} else {
		http.Redirect(w, r, errorPageURL, http.StatusTemporaryRedirect)
	}
}

func checkErr(err error) {
	if err != nil {
		panic("An error occured: " + err.Error())
	}
}

func checkCount(rows *sql.Rows) (count int) {
	for rows.Next() {
		err := rows.Scan(&count)
		checkErr(err)
	}
	return count
}
