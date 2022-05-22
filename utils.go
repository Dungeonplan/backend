package main

import (
	"database/sql"
	"fmt"
	"strings"
	"time"
)

//Generic Response for Successes/Fails
type SuccessResponse struct {
	Success     bool   `json:"success"`
	Description string `json:"description"`
}

func checkErr(err error) {
	if err != nil {
		log("Error: " + err.Error())
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

func log(message string) {
	fmt.Println(time.Now().Format("02.01.2006 - 15:04:05") + ": " + message)
}
