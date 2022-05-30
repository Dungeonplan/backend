package main

import (
	"encoding/json"
	"net/http"
)

func (env *Env) enableCors(w *http.ResponseWriter) {
	//TODO: Fill real CORS values.
	(*w).Header().Set("Access-Control-Allow-Origin", "*")
	(*w).Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
	(*w).Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")
}

func (env *Env) handleVersion(w http.ResponseWriter, r *http.Request) {
	env.enableCors(&w)
	if (*r).Method == "OPTIONS" {
		return
	}
	// Accept only GET
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	type versionResponse struct {
		Version string `json:"version"`
		Build   int    `json:"build"`
	}

	response := versionResponse{Version: dungeonplan_version, Build: dungeonplan_build}

	jsn, err := json.Marshal(response)
	checkErr(err)
	w.Header().Set("Content-Type", "application/json")
	_, err = w.Write(jsn)
	checkErr(err)
}
