package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/gorilla/mux"
	_ "github.com/mattn/go-sqlite3"
)

// User model
type User struct {
	ID       uint   `gorm:"primaryKey"`
	Username string `gorm:"uniqueIndex"`
	Email    string
	Password string
}

const DATABASE = "./minitwit.db"

// connectDB initializes and returns a database connection
func connectDB() (*sql.DB, error) {
	// TODO Use db as a global variable.
	db, err := sql.Open("sqlite3", DATABASE)
	if err != nil {
		return nil, err
	}
	if err = db.Ping(); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

func initDB() error {
	// Read the schema file using os.ReadFile
	schema, err := os.ReadFile("schema.sql")
	if err != nil {
		return err // Return an error if the file can't be read
	}

	// Execute the schema script
	db, err := connectDB()
	if err == nil {
		_, err = db.Exec(string(schema))
	}
	if err != nil {
		return err // Return an error if the execution fails
	}
	db.Close()

	return nil
}

// Middleware to manage database connection per request
func dbMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Open a new database connection
		db, err := sql.Open("sqlite3", DATABASE)
		fmt.Println("Opening database connection")
		if err != nil {
			fmt.Println(err.Error())
			http.Error(w, "Database connection error", http.StatusInternalServerError)
			return
		}
		defer db.Close() // Close the connection after handling request

		// Store db in context for handlers
		ctx := r.Context()
		ctx = context.WithValue(ctx, "db", db)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Retrieve DB connection from request context
func getDBFromContext(r *http.Request) (*sql.DB, error) {
	db, ok := r.Context().Value("db").(*sql.DB)
	if !ok {
		return nil, os.ErrInvalid
	}
	return db, nil
}

func main() {
	initDB()
	r := mux.NewRouter()
	r.Use(dbMiddleware) // Apply the middleware

	http.Handle("/", r)
	log.Println("Server running on port 5001")
	http.ListenAndServe(":5001", nil)
}
