package main

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/Dungeonplan/backend/security"
	"github.com/gorilla/mux"
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
	// Activate foreign key checks
	_, err = db.Exec("PRAGMA foreign_keys = ON;")
	checkErr(err)

	dev := os.Getenv("DUNGEONPLAN_ENV")

	if dev != "prod" {
		dev = "dev"
	}

	return &Env{database: db, environment: dev}
}

func main() {
	log(fmt.Sprintf("Starting Dungeonplan Backend v%s (Build %d)", dungeonplan_version, dungeonplan_build))
	env := setupEnv()

	router := mux.NewRouter()

	//OAuth2 & Authorization
	router.HandleFunc("/api/logindiscord", env.handleLoginDiscord).Methods("GET", "OPTIONS")
	router.HandleFunc("/api/logindiscordcallback", env.handleLoginDiscordCallback).Methods("GET", "OPTIONS")
	router.HandleFunc("/api/tokenexchange", env.handleTokenExchange).Methods("POST", "OPTIONS")
	router.HandleFunc("/api/logout", env.handleLogout).Methods("GET", "OPTIONS")

	//Roles and Actions
	router.HandleFunc("/api/addrole", env.handleRoleCreation).Methods("POST", "OPTIONS")
	router.HandleFunc("/api/deleterole/{roleid}", env.handleRoleDeletion).Methods("DELETE", "OPTIONS")
	router.HandleFunc("/api/updateroles", env.handleRoleUpdates).Methods("PATCH", "OPTIONS")

	//misc
	router.HandleFunc("/api/version", env.handleVersion)

	restServer := &http.Server{
		Handler:      router,
		Addr:         "0.0.0.0:8123",
		WriteTimeout: time.Second * 15,
		ReadTimeout:  time.Second * 15,
		IdleTimeout:  time.Second * 60,
	}

	err := restServer.ListenAndServe()
	checkErr(err)

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)

	go func() {
		for sig := range c {
			log(sig.String())
			err := env.database.Close()
			checkErr(err)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second*15)
			defer cancel()
			err = restServer.Shutdown(ctx)
			checkErr(err)
			// Code sig c
			os.Exit(130)
		}
	}()
}
