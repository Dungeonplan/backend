package main

import (
	"fmt"
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

	//false
	log(fmt.Sprintf("User can kill animals: %t", env.authorized(jwtToken, "kill_animals")))

	//true
	log(fmt.Sprintf("User can kill unicorns: %t", env.authorized(jwtToken, "kill_unicorn")))

}
