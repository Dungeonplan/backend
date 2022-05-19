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

	http.HandleFunc("/api/logindiscord", env.handleLoginDiscord)
	http.HandleFunc("/api/logindiscordcallback", env.handleLoginDiscordCallback)
	http.ListenAndServe(":8123", nil)
}
