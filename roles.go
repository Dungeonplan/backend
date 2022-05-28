package main

import (
	"encoding/json"
	"net/http"
)

func (env *Env) handleRoleCreation(w http.ResponseWriter, r *http.Request) {
	// Accept only POST
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	// Return 401 if user is not authenticated
	if !env.authenticated(w, r) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	jwtToken := extractBearerToken(r.Header.Get("Authorization"))

	// Return 401 if user has no rights to add roles
	if !env.authorized(jwtToken, action_role_add) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	type createRoleRequest struct {
		ShortName   string `json:"short_name"`
		Description string `json:"description"`
		Hierarchy   int    `json:"hierarchy"`
	}

	w.Header().Set("Content-Type", "application/json")

	var req createRoleRequest

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	err := decoder.Decode(&req)
	if err != nil {
		checkErr(err)
		body := SuccessResponse{Success: false, Description: "Could not create rule. Could not parse request."}
		jsn, err := json.Marshal(body)
		checkErr(err)
		w.WriteHeader(http.StatusBadRequest)
		_, err = w.Write(jsn)
		checkErr(err)
		return
	}

	stmt, err := env.database.Prepare("INSERT INTO role(short_name, description, hierarchy) VALUES (?, ?, ?);")
	checkErr(err)
	_, err = stmt.Exec(req.ShortName, req.Description, req.Hierarchy)
	if err != nil {
		checkErr(err)
		body := SuccessResponse{Success: false, Description: "Could not create rule. Short name already exists."}
		jsn, err := json.Marshal(body)
		checkErr(err)
		w.WriteHeader(http.StatusBadRequest)
		_, err = w.Write(jsn)
		checkErr(err)
		return
	}

	body := SuccessResponse{Success: true, Description: "Role successfully added."}
	jsn, err := json.Marshal(body)
	checkErr(err)
	_, err = w.Write(jsn)
	checkErr(err)
}
