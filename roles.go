package main

import (
	"encoding/json"
	"github.com/gorilla/mux"
	"net/http"
	"strconv"
)

func (env *Env) handleRoleCreation(w http.ResponseWriter, r *http.Request) {
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

func (env *Env) handleRoleDeletion(w http.ResponseWriter, r *http.Request) {
	// Return 401 if user is not authenticated
	if !env.authenticated(w, r) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	roleID, err := strconv.Atoi(mux.Vars(r)["roleid"])

	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	jwtToken := extractBearerToken(r.Header.Get("Authorization"))

	// Return 401 if user has no rights to add roles
	if !env.authorized(jwtToken, action_role_delete) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	// Check if Role is System
	row := env.database.QueryRow("SELECT system FROM role WHERE id = ?", roleID)
	var system bool
	err = row.Scan(&system)
	checkErr(err)

	if system {
		body := SuccessResponse{Success: false, Description: "System roles can't be deleted."}
		jsn, err := json.Marshal(body)
		checkErr(err)
		_, err = w.Write(jsn)
		checkErr(err)
		return
	}

	// Check if any User has this role
	row = env.database.QueryRow("SELECT COUNT(*) FROM user WHERE role = ?", roleID)
	var userWithRole int
	err = row.Scan(&userWithRole)
	checkErr(err)

	if userWithRole > 0 {
		body := SuccessResponse{Success: false, Description: "They're still users with this role."}
		jsn, err := json.Marshal(body)
		checkErr(err)
		_, err = w.Write(jsn)
		checkErr(err)
		return
	}

	// TODO: Add "ON DELETE CASCADE"
	// DELETE Role
	stmt, err := env.database.Prepare("DELETE FROM role WHERE id = ?")
	checkErr(err)
	_, err = stmt.Exec(roleID)
	checkErr(err)
	var body SuccessResponse
	if err != nil {
		body = SuccessResponse{Success: false, Description: "Could not delete role: " + err.Error()}
	} else {
		body = SuccessResponse{Success: true, Description: "Role was successfully deleted."}
	}
	jsn, err := json.Marshal(body)
	checkErr(err)
	_, err = w.Write(jsn)
	checkErr(err)
}
