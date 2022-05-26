package main

import (
	"encoding/json"
	"net/http"
)

func (env *Env) handleVersion(w http.ResponseWriter, r *http.Request) {
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
