package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"

	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

const DATABASE = "./minitwit.db"
const PER_PAGE = 30 // Number of messages per page

var db *sql.DB

// Message represents a single message in the public timeline
type Message struct {
	ID       int    `json:"id"`
	AuthorID int    `json:"author_id"`
	Username string `json:"username"`
	Text     string `json:"text"`
	PubDate  int64  `json:"pub_date"`
}

// User represents a user in the database
type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
	PwHash   string `json:"pw_hash"`
}

var store = sessions.NewCookieStore([]byte("something-very-secret"))

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

	return nil
}

func getUserID(db *sql.DB, username string) (int, error) {
	var userID int
	err := db.QueryRow("SELECT user_id FROM user WHERE username = ?", username).Scan(&userID)

	if err == sql.ErrNoRows {
		// If no user is found, return 0 (or any other value that indicates not found) and nil error
		return -1, nil
	}
	if err != nil {
		return 0, err // Return any other error that occurs during the query
	}

	return userID, nil
}

func timelineHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session-name")
	userID, ok := session.Values["user_id"].(int)
	if !ok || userID == 0 {
		http.Redirect(w, r, "/public", http.StatusFound)
		return
	}

	db, err := connectDB()
	if err != nil {
		http.Error(w, "Database connection error", http.StatusInternalServerError)
		return
	}
	defer db.Close()

	offset := r.URL.Query().Get("offset")
	if offset == "" {
		offset = "0"
	}

	rows, err := db.Query(`
        SELECT message.message_id, message.author_id, user.username, message.text, message.pub_date
        FROM message
        JOIN user ON message.author_id = user.user_id
        WHERE message.flagged = 0 AND (user.user_id = ? OR user.user_id IN (SELECT whom_id FROM follower WHERE who_id = ?))
        ORDER BY message.pub_date DESC
        LIMIT ? OFFSET ?`, userID, userID, PER_PAGE, offset)
	if err != nil {
		http.Error(w, "Database query error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var messages []Message

	for rows.Next() {
		var msg Message
		if err := rows.Scan(&msg.ID, &msg.AuthorID, &msg.Username, &msg.Text, &msg.PubDate); err != nil {
			http.Error(w, "Error scanning database results", http.StatusInternalServerError)
			return
		}
		messages = append(messages, msg)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(messages)
}

// publicTimelineHandler handles requests to the /public endpoint
func publicTimelineHandler(w http.ResponseWriter, r *http.Request) {
	db, err := connectDB()
	fmt.Println("trying to connect database")
	fmt.Println(err)
	if err != nil {
		http.Error(w, "Database connection error", http.StatusInternalServerError)
		return
	}
	defer db.Close()

	// Query to fetch the latest public messages
	rows, err := db.Query(`
        SELECT message.message_id, message.author_id, user.username, message.text, message.pub_date
        FROM message
        JOIN user ON message.author_id = user.user_id
        WHERE message.flagged = 0
        ORDER BY message.pub_date DESC
        LIMIT ?`, PER_PAGE)
	if err != nil {
		http.Error(w, "Database query error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var messages []Message

	// Loop through results and append to messages slice
	for rows.Next() {
		var msg Message
		if err := rows.Scan(&msg.ID, &msg.AuthorID, &msg.Username, &msg.Text, &msg.PubDate); err != nil {
			http.Error(w, "Error scanning database results", http.StatusInternalServerError)
			return
		}
		messages = append(messages, msg)
	}

	// Convert messages to JSON and send response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(messages)
}

func sendErrorResponse(w http.ResponseWriter, errorMessage string) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"error": errorMessage})
}

// loginHandler handles login requests
func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		// Render the login form here (e.g., serve an HTML page)
		http.ServeFile(w, r, "templates/login.html")
		return
	}

	if r.Method == http.MethodPost {
		username := r.FormValue("username")
		password := r.FormValue("password")

		// Validate form data
		if username == "" {
			sendErrorResponse(w, "You have to enter a username")
			return
		} else if password == "" {
			sendErrorResponse(w, "You have to enter a password")
			return
		}

		db, err := connectDB()
		if err != nil {
			sendErrorResponse(w, "Database connection error")
			return
		}
		defer db.Close()

		var user User
		err = db.QueryRow("SELECT user_id, username, pw_hash FROM user WHERE username = ?", username).Scan(&user.ID, &user.Username, &user.PwHash)
		if err != nil {
			sendErrorResponse(w, "Invalid username")
			return
		} else if err := bcrypt.CompareHashAndPassword([]byte(user.PwHash), []byte(password)); err != nil {
			sendErrorResponse(w, "Invalid password")
			return
		} else {
			// Start a session and store the user ID in the session
			session, err := store.Get(r, "session-name")
			if err != nil {
				sendErrorResponse(w, "Failed to get session")
				return
			}

			// Store user_id in the session
			session.Values["user_id"] = user.ID
			err = session.Save(r, w)
			if err != nil {
				sendErrorResponse(w, "Failed to save session")
				return
			}

			fmt.Println("User logged in", session.Values["user_id"])
			// Respond with a success message
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"message": "You were logged in"})
			return
		}
	}
}

// registerHandler handles registration requests
func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		// TODO: Render the registration form here (e.g., serve an HTML page)
		http.ServeFile(w, r, "templates/register.html")
		return
	}

	if r.Method == http.MethodPost {
		username := r.FormValue("username")
		email := r.FormValue("email")
		password := r.FormValue("password")
		password2 := r.FormValue("password2")

		// Validate form data
		if username == "" {
			sendErrorResponse(w, "You have to enter a username")
			return
		} else if email == "" || !regexp.MustCompile(`^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}$`).MatchString(email) {
			sendErrorResponse(w, "You have to enter a valid email address")
			return
		} else if password == "" {
			sendErrorResponse(w, "You have to enter a password")
			return
		} else if password != password2 {
			sendErrorResponse(w, "The two passwords do not match")
			return
		}

		db, err := connectDB()
		if err != nil {
			sendErrorResponse(w, "Database connection error")
			return
		}
		defer db.Close()

		// Check if the username already exists
		userID, err := getUserID(db, username)
		if err != nil {
			sendErrorResponse(w, "Database query error")
			return
		}
		if userID != -1 {
			// If userID is non-zero, it means the username already exists
			json.NewEncoder(w).Encode(map[string]string{"error": "The username is already taken"})
			return
		}

		// Hash the password
		pwHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			sendErrorResponse(w, "Error hashing password")
			return
		}

		// Insert user into database
		_, err = db.Exec("INSERT INTO user (username, email, pw_hash) VALUES (?, ?, ?)", username, email, pwHash)
		if err != nil {
			sendErrorResponse(w, "Error inserting user into database")
			return
		}

		// Respond with success message
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"message": "You were successfully registered and can login now"})
		return
	}

	// TODO: Render html
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	// Get the session
	session, err := store.Get(r, "session-name")
	if err != nil {
		http.Error(w, "Unable to retrieve session", http.StatusInternalServerError)
		return
	}

	// Remove the 'user_id' from the session
	delete(session.Values, "user_id")

	// Save the session after modification
	err = session.Save(r, w)
	if err != nil {
		http.Error(w, "Unable to save session", http.StatusInternalServerError)
		return
	}

	fmt.Println("User logged out", session.Values["user_id"])
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "You were logged out"})
	// TODO Redirecting to timeline
}

func userTimelineHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	username := vars["username"]

	db, err := connectDB()
	if err != nil {
		http.Error(w, "Database connection error", http.StatusInternalServerError)
		return
	}
	defer db.Close()

	var profileUser User
	err = db.QueryRow("SELECT user_id, username FROM user WHERE username = ?", username).Scan(&profileUser.ID, &profileUser.Username)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	session, _ := store.Get(r, "session-name")
	userID, ok := session.Values["user_id"].(int)
	followed := false
	if ok && userID != 0 {
		var count int
		err = db.QueryRow("SELECT COUNT(*) FROM follower WHERE who_id = ? AND whom_id = ?", userID, profileUser.ID).Scan(&count)
		if err == nil && count > 0 {
			followed = true
		}
	}

	rows, err := db.Query(`
        SELECT message.message_id, message.author_id, user.username, message.text, message.pub_date
        FROM message
        JOIN user ON message.author_id = user.user_id
        WHERE user.user_id = ?
        ORDER BY message.pub_date DESC
        LIMIT ?`, profileUser.ID, PER_PAGE)
	if err != nil {
		http.Error(w, "Database query error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var messages []Message

	for rows.Next() {
		var msg Message
		if err := rows.Scan(&msg.ID, &msg.AuthorID, &msg.Username, &msg.Text, &msg.PubDate); err != nil {
			http.Error(w, "Error scanning database results", http.StatusInternalServerError)
			return
		}
		messages = append(messages, msg)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"messages":     messages,
		"followed":     followed,
		"profile_user": profileUser,
	})
}

func followUserHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session-name")
	userID, ok := session.Values["user_id"].(int)
	if !ok || userID == 0 {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	vars := mux.Vars(r)
	username := vars["username"]

	db, err := connectDB()
	if err != nil {
		http.Error(w, "Database connection error", http.StatusInternalServerError)
		return
	}
	defer db.Close()

	var whomID int
	err = db.QueryRow("SELECT user_id FROM user WHERE username = ?", username).Scan(&whomID)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	_, err = db.Exec("INSERT INTO follower (who_id, whom_id) VALUES (?, ?)", userID, whomID)
	if err != nil {
		http.Error(w, "Error inserting follower into database", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "You are now following " + username})
}

func unfollowUserHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session-name")
	userID, ok := session.Values["user_id"].(int)
	if !ok || userID == 0 {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	vars := mux.Vars(r)
	username := vars["username"]

	db, err := connectDB()
	if err != nil {
		http.Error(w, "Database connection error", http.StatusInternalServerError)
		return
	}
	defer db.Close()

	var whomID int
	err = db.QueryRow("SELECT user_id FROM user WHERE username = ?", username).Scan(&whomID)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	_, err = db.Exec("DELETE FROM follower WHERE who_id = ? AND whom_id = ?", userID, whomID)
	if err != nil {
		http.Error(w, "Error deleting follower from database", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "You are no longer following " + username})
}

func addMessageHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session-name")
	fmt.Printf("Raw session values: %+v\n", session.Values)

	userID, ok := session.Values["user_id"].(int)
	fmt.Printf("user_id in session: %v, Type: %T\n", session.Values["user_id"], session.Values["user_id"])
	if !ok || userID == 0 {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	text := r.FormValue("text")

	db, err := connectDB()
	if err != nil {
		// TODO: This if condition can be generalized inside connectDB function
		sendErrorResponse(w, "Database connection error")
		return
	}
	defer db.Close()

	_, err = db.Exec("INSERT INTO message (author_id, text, pub_date, flagged) VALUES (?, ?, ?, 0)", userID, text, time.Now().Unix())
	if err != nil {
		http.Error(w, "Error inserting message into database", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "Your message was recorded"})
}

func main() {
	r := mux.NewRouter()
	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   86400, // 1 day
		HttpOnly: true,
		Secure:   false, // Must be true in production with HTTPS
		SameSite: http.SameSiteLaxMode,
	}

	r.HandleFunc("/public", publicTimelineHandler).Methods("GET")
	r.HandleFunc("/login", loginHandler).Methods("POST", "GET")
	r.HandleFunc("/register", registerHandler).Methods("POST", "GET")
	r.HandleFunc("/logout", logoutHandler).Methods("GET")
	r.HandleFunc("/", timelineHandler).Methods("GET")
	r.HandleFunc("/{username}", userTimelineHandler).Methods("GET")
	r.HandleFunc("/{username}/follow", followUserHandler).Methods("GET")
	r.HandleFunc("/{username}/unfollow", unfollowUserHandler).Methods("GET")
	r.HandleFunc("/add_message", addMessageHandler).Methods("POST")

	log.Println("Server started on :5000")
	log.Fatal(http.ListenAndServe(":5000", r))
}
