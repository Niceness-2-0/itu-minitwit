package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/gorilla/mux"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
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

// updateLatest writes the latest processed command ID to a file
func updateLatest(r *http.Request) {
	latest := r.URL.Query().Get("latest")
	if latest == "" {
		return
	}

	parsedCommandID, err := strconv.Atoi(latest)
	if err != nil || parsedCommandID == -1 {
		return
	}

	err = os.WriteFile("latest_processed_sim_action_id.txt", []byte(strconv.Itoa(parsedCommandID)), 0644)
	if err != nil {
		fmt.Println("Error writing latest ID:", err)
	}
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	updateLatest(r)

	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var requestData struct {
		Username string `json:"username"`
		Email    string `json:"email"`
		Password string `json:"pwd"`
	}

	if err := json.NewDecoder(r.Body).Decode(&requestData); err != nil {
		http.Error(w, `{"status": 400, "error_msg": "Invalid JSON"}`, http.StatusBadRequest)
		return
	}

	// Validate inputs
	if requestData.Username == "" {
		http.Error(w, `{"status": 400, "error_msg": "You have to enter a username"}`, http.StatusBadRequest)
		return
	}
	if requestData.Email == "" || !strings.Contains(requestData.Email, "@") {
		http.Error(w, `{"status": 400, "error_msg": "You have to enter a valid email address"}`, http.StatusBadRequest)
		return
	}
	if requestData.Password == "" {
		http.Error(w, `{"status": 400, "error_msg": "You have to enter a password"}`, http.StatusBadRequest)
		return
	}

	db, err := getDBFromContext(r)

	// Check if username exists
	var exists bool
	err = db.QueryRow("SELECT EXISTS(SELECT 1 FROM user WHERE username = ?)", requestData.Username).Scan(&exists)
	if err != nil {
		http.Error(w, `{"status": 500, "error_msg": "Database error"}`, http.StatusInternalServerError)
		return
	}
	if exists {
		http.Error(w, `{"status": 400, "error_msg": "The username is already taken"}`, http.StatusBadRequest)
		return
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(requestData.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, `{"status": 500, "error_msg": "Error hashing password"}`, http.StatusInternalServerError)
		return
	}

	// Insert user
	_, err = db.Exec("INSERT INTO user (username, email, pw_hash) VALUES (?, ?, ?)", requestData.Username, requestData.Email, string(hashedPassword))
	if err != nil {
		http.Error(w, `{"status": 500, "error_msg": "Database error"}`, http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func main() {
	initDB()
	r := mux.NewRouter()
	r.Use(dbMiddleware) // Apply the middleware

	r.HandleFunc("/register", registerHandler).Methods("POST", "GET")

	http.Handle("/", r)
	log.Println("Server running on port 5001")
	http.ListenAndServe(":5001", nil)
}
