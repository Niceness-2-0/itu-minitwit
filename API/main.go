package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

// User model
type User struct {
	ID       uint   `gorm:"primaryKey"`
	Username string `gorm:"uniqueIndex"`
	Email    string
	PwHash   string `json:"pw_hash"`
}

// Message represents a message with user from the database
type Message struct {
	Content string `json:"content"`
	PubDate int64  `json:"pub_date"`
	User    string `json:"user"`
}

const DATABASE = "../db/minitwit.db"

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

// Middleware to inject database connection into the request's context
func dbMiddleware(next http.Handler) http.Handler {
	log.Println("dbMiddleware was called...")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Open a new database connection
		db, err := sql.Open("sqlite3", DATABASE)
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

// getUserID fetches the user ID given a username
func getUserID(db *sql.DB, username string) (int, error) {
	var userID int
	err := db.QueryRow("SELECT user_id FROM user WHERE username = ?", username).Scan(&userID)
	if err != nil {
		if err == sql.ErrNoRows {
			return 0, err // User not found
		}
		return 0, err
	}
	return userID, nil
}

// getLatest reads the latest processed command ID from a file and returns it as JSON
func getLatest(w http.ResponseWriter, r *http.Request) {
	data, err := os.ReadFile("latest_processed_sim_action_id.txt")
	if err != nil {
		// If the file doesn't exist or there's an error reading, default to -1
		log.Println(fmt.Errorf("Error reading latest ID file: %w", err))
		data = []byte("-1")
	}

	latestProcessedID, err := strconv.Atoi(string(data))
	if err != nil {
		latestProcessedID = -1
	}

	response := map[string]int{"latest": latestProcessedID}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// notReqFromSimulator checks if the request is authorized
func notReqFromSimulator(w http.ResponseWriter, r *http.Request) bool {
	fromSimulator := r.Header.Get("Authorization")

	// Expected authorization header value
	expectedAuth := "Basic c2ltdWxhdG9yOnN1cGVyX3NhZmUh"

	if fromSimulator != expectedAuth {
		http.Error(w, `{"status": 400, "error_msg": "You are not authorized to use this resource!"}`, http.StatusForbidden)
		return false
	}

	return true
}

// getMessages
func getMessages(w http.ResponseWriter, r *http.Request) {
	log.Println("getMessages was called")
	updateLatest(r)

	noMsgs := 100 // Default 100 messages
	if noMsgsStr := r.URL.Query().Get("no"); noMsgsStr != "" {
		if num, err := strconv.Atoi(noMsgsStr); err == nil {
			noMsgs = num
		}
	}

	db, _ := getDBFromContext(r)
	// Query messages
	query := `SELECT message.text, message.pub_date, user.username 
	FROM message 
	JOIN user ON message.author_id = user.user_id 
	WHERE message.flagged = 0 
	ORDER BY message.pub_date DESC 
	LIMIT ?`

	rows, err := db.Query(query, noMsgs)
	if err != nil {
		http.Error(w, "Database query error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	// Process results
	var messages []Message
	for rows.Next() {
		var msg Message
		if err := rows.Scan(&msg.Content, &msg.PubDate, &msg.User); err != nil {
			http.Error(w, "Error scanning row", http.StatusInternalServerError)
			return
		}
		messages = append(messages, msg)
	}
	// Send JSON response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(messages)
}

// userFollowing hanldes GET (retrieve messages from the people the user follows)
func userFollowing(w http.ResponseWriter, r *http.Request) {
	log.Println("userFollowing was called")

	vars := mux.Vars(r)
	userID := vars["userID"]

	noMsgs := 100 // Default 100 messages
	if noMsgsStr := r.URL.Query().Get("no"); noMsgsStr != "" {
		if num, err := strconv.Atoi(noMsgsStr); err == nil {
			noMsgs = num
		}
	}

	offset := r.URL.Query().Get("offset")
	if offset == "" {
		offset = "0"
	}

	db, _ := getDBFromContext(r)
	// Query messages
	query := `SELECT message.text, message.pub_date, user.username 
		     FROM message
		     JOIN user ON message.author_id = user.user_id
		     WHERE message.flagged = 0 AND (user.user_id = ? OR user.user_id IN (SELECT whom_id FROM follower WHERE who_id = ?))
		     ORDER BY message.pub_date DESC
		     LIMIT ? OFFSET ?`

	rows, err := db.Query(query, userID, userID, noMsgs, offset)
	if err != nil {
		http.Error(w, "Database query error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	// Process results
	var messages []Message
	for rows.Next() {
		var msg Message
		if err := rows.Scan(&msg.Content, &msg.PubDate, &msg.User); err != nil {
			http.Error(w, "Error scanning row", http.StatusInternalServerError)
			return
		}
		messages = append(messages, msg)
	}
	// Send JSON response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(messages)
}

// messagesPerUser handles GET (retrieve messages) and POST (post a message)
func messagesPerUser(w http.ResponseWriter, r *http.Request) {
	log.Println("messagesPerUser was called")
	updateLatest(r)
	vars := mux.Vars(r)
	username := vars["username"]

	noMsgs := 100 // Default 100 messages
	if noMsgsStr := r.URL.Query().Get("no"); noMsgsStr != "" {
		if num, err := strconv.Atoi(noMsgsStr); err == nil {
			noMsgs = num
		}
	}

	db, _ := getDBFromContext(r)

	// Get user ID
	userID, err := getUserID(db, username)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			http.Error(w, "User not found", http.StatusNotFound)
		} else {
			http.Error(w, "Database error", http.StatusInternalServerError)
		}
		return
	}
	if r.Method == http.MethodGet {

		// Query messages
		query := `SELECT message.text, message.pub_date, user.username 
			FROM message 
			JOIN user ON message.author_id = user.user_id 
			WHERE message.flagged = 0 AND user.user_id = ? 
			ORDER BY message.pub_date DESC 
			LIMIT ?`

		rows, err := db.Query(query, userID, noMsgs)
		if err != nil {
			http.Error(w, "Database query error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()
		// Process results
		var messages []Message
		for rows.Next() {
			var msg Message
			if err := rows.Scan(&msg.Content, &msg.PubDate, &msg.User); err != nil {
				http.Error(w, "Error scanning row", http.StatusInternalServerError)
				return
			}
			messages = append(messages, msg)
		}
		// Send JSON response
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(messages)

	} else if r.Method == http.MethodPost {
		if !notReqFromSimulator(w, r) {
			return
		}

		// Decode request body
		var requestData struct {
			Content string `json:"content"`
		}
		if err := json.NewDecoder(r.Body).Decode(&requestData); err != nil {
			http.Error(w, `{"status": 400, "error_msg": "Invalid JSON"}`, http.StatusBadRequest)
			return
		}

		// Insert message into DB
		query := `INSERT INTO message (author_id, text, pub_date, flagged)
				  VALUES (?, ?, ?, 0)`

		_, err = db.Exec(query, userID, requestData.Content, time.Now().Unix())
		if err != nil {
			http.Error(w, "Database insert error", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

// follow handles GET (retrieve followers) and POST (follow, unfollow a user)
func follow(w http.ResponseWriter, r *http.Request) {
	log.Println("follow was called")
	updateLatest(r)
	vars := mux.Vars(r)
	username := vars["username"]

	if !notReqFromSimulator(w, r) {
		return
	}

	db, _ := getDBFromContext(r)

	// Get user ID
	userID, err := getUserID(db, username)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			http.Error(w, "User not found", http.StatusNotFound)
		} else {
			http.Error(w, "Database error", http.StatusInternalServerError)
		}
		return
	}

	if r.Method == http.MethodPost {
		// Decode request body
		var requestData struct {
			FollowUsername   string `json:"follow"`
			UnFollowUsername string `json:"unfollow"`
		}
		if err := json.NewDecoder(r.Body).Decode(&requestData); err != nil {
			http.Error(w, `{"status": 400, "error_msg": "Invalid JSON"}`, http.StatusBadRequest)
			return
		}

		if requestData.FollowUsername != "" {
			// Get user ID
			followsUserID, err := getUserID(db, requestData.FollowUsername)
			if err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					http.Error(w, "User not found", http.StatusNotFound)
				} else {
					http.Error(w, "Database error", http.StatusInternalServerError)
				}
				return
			}

			// Follow the user
			query := `INSERT INTO follower (who_id, whom_id) VALUES (?, ?)`
			_, err = db.Exec(query, userID, followsUserID)
			if err != nil {
				http.Error(w, "Database insert error", http.StatusInternalServerError)
				return
			}

			// Send JSON response
			w.WriteHeader(http.StatusNoContent)
		} else if requestData.UnFollowUsername != "" {
			// Get user ID
			unfollowUserID, err := getUserID(db, requestData.UnFollowUsername)
			if err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					http.Error(w, "User not found", http.StatusNotFound)
				} else {
					http.Error(w, "Database error", http.StatusInternalServerError)
				}
				return
			}

			// Unfollow the user
			query := `DELETE FROM follower WHERE who_id = ? AND whom_id = ?`
			_, err = db.Exec(query, userID, unfollowUserID)
			if err != nil {
				http.Error(w, "Database insert error", http.StatusInternalServerError)
				return
			}

			w.WriteHeader(http.StatusNoContent)
		}
	} else if r.Method == http.MethodGet {
		noFollowers := 100 // Default 100 followers
		if noFollowersStr := r.URL.Query().Get("no"); noFollowersStr != "" {
			if num, err := strconv.Atoi(noFollowersStr); err == nil {
				noFollowers = num
			}
		}

		// Query followers
		query := `SELECT user.username FROM user
					INNER JOIN follower ON follower.whom_id=user.user_id
					WHERE follower.who_id=?
					LIMIT ?`
		rows, err := db.Query(query, userID, noFollowers)
		if err != nil {
			http.Error(w, "Database query error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		// Collect follower usernames
		var followerNames []string
		for rows.Next() {
			var username string
			if err := rows.Scan(&username); err != nil {
				http.Error(w, "Error scanning result", http.StatusInternalServerError)
				return
			}
			followerNames = append(followerNames, username)
		}

		// Prepare JSON response
		response := map[string][]string{"follows": followerNames}
		// Send JSON response
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}
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

func loginHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("loginHandler was called")
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	var creds struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	db, err := connectDB()
	if err != nil {
		http.Error(w, "Database connection error", http.StatusInternalServerError)
		return
	}
	defer db.Close()

	var user User
	err = db.QueryRow("SELECT user_id, username, pw_hash FROM user WHERE username = ?", creds.Username).Scan(&user.ID, &user.Username, &user.PwHash)
	if err != nil {
		http.Error(w, "Invalid username", http.StatusUnauthorized)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PwHash), []byte(creds.Password)); err != nil {
		http.Error(w, "Invalid password", http.StatusUnauthorized)
		return
	}

	response := map[string]string{
		"user_id":  fmt.Sprintf("%d", user.ID),
		"username": user.Username,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("registerHandler was called")
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

	db, _ := getDBFromContext(r)

	// Check if username exists
	var exists bool
	err := db.QueryRow("SELECT EXISTS(SELECT 1 FROM user WHERE username = ?)", requestData.Username).Scan(&exists)
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
	r := mux.NewRouter()
	r.Use(dbMiddleware) // Apply the middleware to all endpoints defined in the router

	r.HandleFunc("/login", loginHandler).Methods("POST", "GET")
	r.HandleFunc("/register", registerHandler).Methods("POST", "GET")
	r.HandleFunc("/latest", getLatest).Methods("GET")
	r.HandleFunc("/msgs", getMessages).Methods("GET")
	r.HandleFunc("/msgs/{username}", messagesPerUser).Methods("GET", "POST")
	r.HandleFunc("/fllws/{username}", follow).Methods("GET", "POST")
	r.HandleFunc("/following/{userID}", userFollowing).Methods("GET")

	http.Handle("/", r)
	log.Println("Server running on port 5001")
	http.ListenAndServe(":5001", nil)
}
