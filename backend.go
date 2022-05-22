package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"os/signal"

	"github.com/Dungeonplan/backend/security"
	_ "github.com/mattn/go-sqlite3"
)

type Env struct {
	database    *sql.DB
	environment string
}

func init() {
	security.AssertAvailablePRNG()
}

func setupEnv() *Env {
	db, err := sql.Open("sqlite3", "./database.sqlite")
	checkErr(err)
	dev := os.Getenv("DUNGEONPLAN_ENV")

	if dev != "prod" {
		dev = "dev"
	}

	return &Env{database: db, environment: dev}
}

func main() {

	env := setupEnv()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		for sig := range c {
			fmt.Println(sig.String())
			env.database.Close()
			// Code sig c
			os.Exit(130)
		}
	}()

	http.HandleFunc("/api/logindiscord", env.handleLoginDiscord)
	http.HandleFunc("/api/logindiscordcallback", env.handleLoginDiscordCallback)
	http.HandleFunc("/api/tokenexchange", env.handleTokenExchange)
	http.HandleFunc("/api/logout", env.handleLogout)
	http.ListenAndServe(":8123", nil)
}
