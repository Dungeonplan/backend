package main

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
)

func (env *Env) handleGetRoles(w http.ResponseWriter, r *http.Request) {
	env.enableCors(&w)
	if (*r).Method == "OPTIONS" {
		return
	}

	// Return 401 if user is not authenticated
	if !env.authenticated(w, r) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// TODO: doppelt vorhanden (siehe authorization.go)
	type action struct {
		ID          int    `json:"id"`
		ShortName   string `json:"short_name"`
		Description string `json:"description"`
	}

	type role struct {
		ID          int      `json:"id"`
		ShortName   string   `json:"short_name"`
		Description string   `json:"description"`
		Hierarchy   int      `json:"hierarchy"`
		System      bool     `json:"system"`
		Actions     []action `json:"actions"`
	}

	rows, err := env.database.Query("SELECT id, short_name, description, hierarchy, system FROM role ORDER BY hierarchy")
	checkErr(err)
	var roles []role
	for rows.Next() {
		role := role{}
		var system int
		err = rows.Scan(&role.ID, &role.ShortName, &role.Description, &role.Hierarchy, &system)
		if system == 0 {
			role.System = false
		} else {
			role.System = true
		}

		rows_action, err := env.database.Query("SELECT action.id, action.short_name, action.description FROM role_action INNER JOIN action ON role_action.action_id = action.id WHERE role_action.role_id = ?", role.ID)
		checkErr(err)
		actions := []action{}
		for rows_action.Next() {
			action := action{}
			err = rows_action.Scan(&action.ID, &action.ShortName, &action.Description)
			checkErr(err)
			actions = append(actions, action)
		}
		role.Actions = actions
		roles = append(roles, role)
	}

	jsn, err := json.Marshal(roles)
	checkErr(err)
	w.Header().Set("Content-Type", "application/json")
	_, err = w.Write(jsn)
	checkErr(err)

}

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

	// Delete Role
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

func (env *Env) handleRoleUpdates(w http.ResponseWriter, r *http.Request) {
	// Return 401 if user is not authenticated
	if !env.authenticated(w, r) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	jwtToken := extractBearerToken(r.Header.Get("Authorization"))

	// Return 401 if user has no rights to add roles
	if !env.authorized(jwtToken, action_role_update) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	type updateRolesRequest struct {
		ID          int    `json:"id"`
		ShortName   string `json:"short_name"`
		Description string `json:"description"`
		Hierarchy   int    `json:"hierarchy"`
	}

	w.Header().Set("Content-Type", "application/json")

	var updates []updateRolesRequest

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	err := decoder.Decode(&updates)
	if err != nil {
		checkErr(err)
		body := SuccessResponse{Success: false, Description: "Could not update rules. Could not parse request."}
		jsn, err := json.Marshal(body)
		checkErr(err)
		w.WriteHeader(http.StatusBadRequest)
		_, err = w.Write(jsn)
		checkErr(err)
		return
	}

	var hierarchy []int
	for _, v := range updates {
		hierarchy = append(hierarchy, v.Hierarchy)
	}

	if hasIntSliceDuplicates(hierarchy) {
		body := SuccessResponse{Success: false, Description: "Could not update rules. Duplicate hierarchies."}
		jsn, err := json.Marshal(body)
		checkErr(err)
		w.WriteHeader(http.StatusBadRequest)
		_, err = w.Write(jsn)
		checkErr(err)
		return
	}

	for _, v := range updates {
		stmt, err := env.database.Prepare("UPDATE role SET short_name = ?, description = ?, hierarchy = ? WHERE id = ?")
		checkErr(err)
		_, err = stmt.Exec(v.ShortName, v.Description, v.Hierarchy, v.ID)
		checkErr(err)
	}

	body := SuccessResponse{Success: true, Description: "Roled updated successfully."}
	jsn, err := json.Marshal(body)
	checkErr(err)
	_, err = w.Write(jsn)
	checkErr(err)
}

func (env *Env) handleGetActions(w http.ResponseWriter, r *http.Request) {
	env.enableCors(&w)
	if (*r).Method == "OPTIONS" {
		return
	}

	// Return 401 if user is not authenticated
	if !env.authenticated(w, r) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// TODO: Doppelt und dreifach vorhanden
	type action struct {
		ID          int    `json:"id"`
		ShortName   string `json:"short_name"`
		Description string `json:"description"`
	}

	rows, err := env.database.Query("SELECT * FROM action ORDER BY short_name ASC")
	checkErr(err)

	var actions []action
	for rows.Next() {
		action := action{}
		err = rows.Scan(&action.ID, &action.ShortName, &action.Description)
		actions = append(actions, action)
	}

	jsn, err := json.Marshal(actions)
	checkErr(err)
	w.Header().Set("Content-Type", "application/json")
	_, err = w.Write(jsn)
	checkErr(err)
}
