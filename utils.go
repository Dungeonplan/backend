package main

import (
	"database/sql"
	"strings"
)

//Generic Response for Successes/Fails
type SuccessResponse struct {
	Success     bool   `json:"success"`
	Description string `json:"description"`
}

func checkErr(err error) {
	if err != nil {
		panic("An error occured: " + err.Error())
	}
}

func checkRowsCount(rows *sql.Rows) (count int) {
	for rows.Next() {
		err := rows.Scan(&count)
		checkErr(err)
	}
	return count
}

func extractBearerToken(authorizationString string) string {
	return strings.Replace(authorizationString, "Bearer ", "", 1)
}
