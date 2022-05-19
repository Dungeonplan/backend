package main

import "database/sql"

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
