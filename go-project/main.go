package main

import (
	"database/sql"
	"fmt"
	"html/template"
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

// Configurations
const (
	DATABASE = "./minitwit.db"
	PER_PAGE = 30 // Number of messages per page
	SECRET   = "development-key"
)

var (
	store = sessions.NewCookieStore([]byte(SECRET)) // this is stored on the client
)

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

// connectDB initializes and returns a database connection
func connectDB() (*sql.DB, error) {
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
		return err
	}

	// Execute the schema script
	db, err := connectDB()
	if err == nil {
		_, err = db.Exec(string(schema))
	}
	if err != nil {
		return err
	}

	return nil
}

func getUserID(db *sql.DB, username string) (int, error) {
	var userID int
	err := db.QueryRow("SELECT user_id FROM user WHERE username = ?", username).Scan(&userID)

	if err == sql.ErrNoRows {
		return -1, nil
	}
	if err != nil {
		return 0, err
	}

	return userID, nil
}

/*
Shows a users timeline or if no user is logged in it will redirect to the public timeline (/public).
This timeline shows the user's messages as well as all the messages of followed users.

Endpoint - /
*/
func timelineHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("timelineHandler called")

	session, err := store.Get(r, "session-cookie")
	if err != nil {
		http.Error(w, "Unable to retrieve session", http.StatusInternalServerError)
		return
	}

	loggedIn := false
	if (session.Values["authenticated"] != nil) && (session.Values["authenticated"] != false) {
		loggedIn = true
	}

	if !loggedIn {
		if session.IsNew {
			session.Save(r, w) // send the 'Set-Cookie' header only when the session is first created
		}
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
        LIMIT ? OFFSET ?`, session.Values["user_id"], session.Values["user_id"], PER_PAGE, offset)
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

	flashes := session.Flashes()
	session.Save(r, w)

	// Define template data
	data := map[string]interface{}{
		"Title":    "My Timeline",
		"Messages": messages,
		"User":     session.Values["user_id"],
		"Username": session.Values["username"],
		"Flashes":  flashes,
	}

	// Parse (creates a template set) with the needed templates for rendering
	tmpl, err := template.ParseFiles("templates/layout.html", "templates/timeline.html")
	if err != nil {
		http.Error(w, "Template parsing error", http.StatusInternalServerError)
		return
	}

	// Render the template using the base template (layout.html)
	w.Header().Set("Content-Type", "text/html")
	err = tmpl.ExecuteTemplate(w, "layout.html", data)
	if err != nil {
		http.Error(w, "Template rendering error", http.StatusInternalServerError)
		return
	}
}

/*
Displays the latest messages of all users.

Endpoint - /public
*/
func publicTimelineHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("publicTimelineHandler called")

	db, err := connectDB()
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

	session, err := store.Get(r, "session-cookie")
	if err != nil {
		http.Error(w, "Unable to retrieve session", http.StatusInternalServerError)
		return
	}

	flashes := session.Flashes()
	session.Save(r, w)

	// Define template data
	data := map[string]interface{}{
		"Title":    "Public Timeline",
		"Messages": messages,
		"User":     session.Values["user_id"],
		"Username": session.Values["username"],
		"Flashes":  flashes,
	}

	tmpl, err := template.ParseFiles("templates/layout.html", "templates/timeline.html")
	if err != nil {
		http.Error(w, "Template parsing error", http.StatusInternalServerError)
		return
	}

	// Render using the base template
	w.Header().Set("Content-Type", "text/html")
	err = tmpl.ExecuteTemplate(w, "layout.html", data) // this writes the response body (from the server)
	if err != nil {
		http.Error(w, "Template rendering error", http.StatusInternalServerError)
		return
	}
}

/*
Logs the user in the MiniTwit account.
Precondition: A valid account should be existing in the database.

Endpoint - /login
*/
func loginHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("loginHandler called")
	tmpl, err := template.ParseFiles("templates/layout.html", "templates/login.html")
	if err != nil {
		http.Error(w, "Template parsing error", http.StatusInternalServerError)
	}

	session, err := store.Get(r, "session-cookie")
	if err != nil {
		http.Error(w, "Unable to retrieve session", http.StatusInternalServerError)
		return
	}

	if r.Method == http.MethodGet {
		flashes := session.Flashes()
		session.Save(r, w)
		tmpl.ExecuteTemplate(w, "layout.html", map[string]interface{}{
			"Error":    "",
			"Username": "",
			"Flashes":  flashes,
		})
		return
	}

	if r.Method == http.MethodPost {
		username := r.FormValue("username")
		password := r.FormValue("password")

		// Validate form data
		if username == "" {
			w.WriteHeader(http.StatusBadRequest)
			tmpl.ExecuteTemplate(w, "layout.html", map[string]interface{}{
				"Error":    "You have to enter a username",
				"Username": username, // Retain entered username
			})
			return
		} else if password == "" {
			w.WriteHeader(http.StatusBadRequest)
			tmpl.ExecuteTemplate(w, "layout.html", map[string]interface{}{
				"Error":    "You have to enter a password",
				"Username": username,
			})
			return
		}

		db, err := connectDB()
		if err != nil {
			tmpl.ExecuteTemplate(w, "layout.html", map[string]interface{}{
				"Error":    "Database connection error",
				"Username": username,
			})
			return
		}
		defer db.Close()

		var user User
		err = db.QueryRow("SELECT user_id, username, pw_hash FROM user WHERE username = ?", username).Scan(&user.ID, &user.Username, &user.PwHash)
		if err != nil {
			tmpl.ExecuteTemplate(w, "layout.html", map[string]interface{}{
				"Error":    "Invalid username",
				"Username": username,
			})
			return
		} else if err := bcrypt.CompareHashAndPassword([]byte(user.PwHash), []byte(password)); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			tmpl.ExecuteTemplate(w, "layout.html", map[string]interface{}{
				"Error":    "Invalid password",
				"Username": username,
			})
			return
		} else {
			// Store user_id and username in the session
			session.Values["authenticated"] = true
			session.Values["user_id"] = user.ID
			session.Values["username"] = user.Username

			// Redirect to timeline after successful login
			session.AddFlash("You were logged in")
			session.Save(r, w)

			http.Redirect(w, r, "/", http.StatusFound)
		}
	}
}

/*
Registers the user.

Endpoint - /register
*/
func registerHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("registerHandler called")
	tmpl, err := template.ParseFiles("templates/layout.html", "templates/register.html")
	if err != nil {
		http.Error(w, "Template parsing error", http.StatusInternalServerError)
		return
	}

	session, err := store.Get(r, "session-cookie")
	if err != nil {
		http.Error(w, "Unable to retrieve session", http.StatusInternalServerError)
		return
	}

	if r.Method == http.MethodGet {
		w.Header().Set("Content-Type", "text/html")
		err = tmpl.ExecuteTemplate(w, "layout.html", nil)
		if err != nil {
			http.Error(w, "Template rendering error", http.StatusInternalServerError)
			return
		}
		return
	}

	if r.Method == http.MethodPost {
		username := r.FormValue("username")
		email := r.FormValue("email")
		password := r.FormValue("password")
		password2 := r.FormValue("password2")

		// Validate form data
		if username == "" {
			w.WriteHeader(http.StatusBadRequest)
			tmpl.ExecuteTemplate(w, "layout.html", map[string]interface{}{
				"Error":    "You have to enter a username",
				"Username": username, // Retain entered username
			})
			return
		} else if email == "" || !regexp.MustCompile(`^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}$`).MatchString(email) {
			w.WriteHeader(http.StatusBadRequest)
			tmpl.ExecuteTemplate(w, "layout.html", map[string]interface{}{
				"Error":    "You have to enter a valid email address",
				"Username": username, // Retain entered username
				"Email":    email,    // Retain entered email
			})
			return
		} else if password == "" {
			w.WriteHeader(http.StatusBadRequest)
			tmpl.ExecuteTemplate(w, "layout.html", map[string]interface{}{
				"Error":    "You have to enter a password",
				"Username": username, // Retain entered username
				"Email":    email,    // Retain entered email
			})
			return
		} else if password != password2 {
			w.WriteHeader(http.StatusBadRequest)
			tmpl.ExecuteTemplate(w, "layout.html", map[string]interface{}{
				"Error":    "The two passwords do not match",
				"Username": username, // Retain entered username
				"Email":    email,    // Retain entered email
			})
			return
		}

		db, err := connectDB()
		if err != nil {
			tmpl.ExecuteTemplate(w, "layout.html", map[string]interface{}{
				"Error":    "Database connection error",
				"Username": username,
				"Email":    email,
				"Password": password,
			})
			return
		}
		defer db.Close()

		// Check if the username already exists
		userID, err := getUserID(db, username)
		if err != nil {
			tmpl.ExecuteTemplate(w, "layout.html", map[string]interface{}{
				"Error":    "Database query error",
				"Username": username,
				"Email":    email,
				"Password": password,
			})
			return
		}
		if userID != -1 {
			// If userID is non-zero, it means the username already exists
			w.WriteHeader(http.StatusBadRequest) // 400 Bad Request for duplicate username
			tmpl.ExecuteTemplate(w, "layout.html", map[string]interface{}{
				"Error": "The username is already taken",
			})
			return
		}

		// Hash the password
		pwHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			tmpl.ExecuteTemplate(w, "layout.html", map[string]interface{}{
				"Error":    "Error hashing password",
				"Username": username,
			})
			return
		}

		// Insert user into database
		_, err = db.Exec("INSERT INTO user (username, email, pw_hash) VALUES (?, ?, ?)", username, email, pwHash)
		if err != nil {
			tmpl.ExecuteTemplate(w, "layout.html", map[string]interface{}{
				"Error":    "Error inserting user into database",
				"Username": username,
			})
			return
		}

		session.AddFlash("You were successfully registered and can login now")
		session.Save(r, w)

		http.Redirect(w, r, "/login", http.StatusFound)

	}
}

/*
Logs the user out.

Endpoint - /logout
*/
func logoutHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("logoutHandler called")

	session, err := store.Get(r, "session-cookie")
	if err != nil {
		http.Error(w, "Unable to retrieve session", http.StatusInternalServerError)
		return
	}

	// Remove the 'user_id' and username from the session
	session.Values["authenticated"] = false
	delete(session.Values, "user_id")
	delete(session.Values, "username")

	session.AddFlash("You were logged out")

	// Save the session after modification
	session.Save(r, w)

	http.Redirect(w, r, "/public", http.StatusFound)
}

/*
Shows a user's profile, displays their tweets.

Endpoint - /{username}
*/
func userTimelineHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("userTimelineHandler called")
	vars := mux.Vars(r)
	username := vars["username"]

	// Connect to the database
	db, err := connectDB()
	if err != nil {
		http.Error(w, "Database connection error", http.StatusInternalServerError)
		return
	}
	defer db.Close()

	// Fetch profile user data
	var profileUser User
	err = db.QueryRow("SELECT user_id, username FROM user WHERE username = ?", username).Scan(&profileUser.ID, &profileUser.Username)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// Check if the current user is following the profile user
	session, err := store.Get(r, "session-cookie")
	if err != nil {
		http.Error(w, "Unable to retrieve session", http.StatusInternalServerError)
		return
	}

	loggedIn := false
	if (session.Values["authenticated"] != nil) && (session.Values["authenticated"] != false) {
		loggedIn = true
	}

	followed := false
	if loggedIn {
		var count int
		err = db.QueryRow("SELECT COUNT(*) FROM follower WHERE who_id = ? AND whom_id = ?", session.Values["user_id"], profileUser.ID).Scan(&count)
		if err == nil && count > 0 {
			followed = true
		}
	}

	// Fetch messages (tweets)
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

	// Store messages in a slice
	var messages []Message
	for rows.Next() {
		var msg Message
		if err := rows.Scan(&msg.ID, &msg.AuthorID, &msg.Username, &msg.Text, &msg.PubDate); err != nil {
			http.Error(w, "Error scanning database results", http.StatusInternalServerError)
			return
		}
		messages = append(messages, msg)
	}

	flashes := session.Flashes()
	session.Save(r, w)

	// Define template data
	data := map[string]interface{}{
		"ProfileUser": profileUser,
		"Messages":    messages,
		"User":        session.Values["user_id"],
		"Username":    session.Values["username"],
		"Followed":    followed,
		"Flashes":     flashes,
	}

	tmpl, err := template.ParseFiles("templates/layout.html", "templates/timeline.html")
	if err != nil {
		http.Error(w, "Template parsing error", http.StatusInternalServerError)
		return
	}

	// Render using the base template
	w.Header().Set("Content-Type", "text/html")
	err = tmpl.ExecuteTemplate(w, "layout.html", data)
	if err != nil {
		http.Error(w, "Template rendering error", http.StatusInternalServerError)
		return
	}
}

/*
Adds the current user as a follower of the given user.
Postcondition: The followed user's tweets will be visible in the current user's timeline.

Endpoint: /{username}/follow
*/
func followUserHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("followUserHandler called")

	session, err := store.Get(r, "session-cookie")
	if err != nil {
		http.Error(w, "Unable to retrieve session", http.StatusInternalServerError)
		return
	}

	loggedIn := false
	if (session.Values["authenticated"] != nil) && (session.Values["authenticated"] != false) {
		loggedIn = true
	}

	if !loggedIn {
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

	_, err = db.Exec("INSERT INTO follower (who_id, whom_id) VALUES (?, ?)", session.Values["user_id"], whomID)
	if err != nil {
		http.Error(w, "Error inserting follower into database", http.StatusInternalServerError)
		return
	}

	// Set flash message (as in the Flask version)
	flashMessage := fmt.Sprintf("You are now following \"%s\"", username)
	session.AddFlash(flashMessage)
	session.Save(r, w)

	// Redirect to user timeline
	http.Redirect(w, r, "/"+username, http.StatusSeeOther)
}

/*
Removes the current user as follower of the given user

Endpoint: /{username}/unfollow
*/
func unfollowUserHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("unfollowUserHandler called")

	session, err := store.Get(r, "session-cookie")
	if err != nil {
		http.Error(w, "Unable to retrieve session", http.StatusInternalServerError)
		return
	}

	loggedIn := false
	if (session.Values["authenticated"] != nil) && (session.Values["authenticated"] != false) {
		loggedIn = true
	}

	if !loggedIn {
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

	_, err = db.Exec("DELETE FROM follower WHERE who_id = ? AND whom_id = ?", session.Values["user_id"], whomID)
	if err != nil {
		http.Error(w, "Error deleting follower from database", http.StatusInternalServerError)
		return
	}

	flashMessage := fmt.Sprintf("You are no longer following \"%s\"", username)
	session.AddFlash(flashMessage)
	session.Save(r, w)

	// Redirect to user timeline
	http.Redirect(w, r, "/"+username, http.StatusSeeOther)
}

/*
Registers a new message for the user

Endpoint: /add_message
*/
func addMessageHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("addMessageHandler called")

	session, err := store.Get(r, "session-cookie")
	if err != nil {
		http.Error(w, "Unable to retrieve session", http.StatusInternalServerError)
		return
	}

	loggedIn := false
	if (session.Values["authenticated"] != nil) && (session.Values["authenticated"] != false) {
		loggedIn = true
	}

	// Check if the user is logged in
	if !loggedIn {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Get message text from form
	text := r.FormValue("text")
	if text == "" {
		http.Redirect(w, r, "/timeline", http.StatusFound) // Redirect even if empty (like Flask)
		return
	}

	// Connect to database
	db, err := connectDB()
	if err != nil {
		http.Error(w, "Database connection error", http.StatusInternalServerError)
		return
	}
	defer db.Close()

	// Insert message into the database
	_, err = db.Exec("INSERT INTO message (author_id, text, pub_date, flagged) VALUES (?, ?, ?, 0)", session.Values["user_id"], text, time.Now().Unix())
	if err != nil {
		http.Error(w, "Error inserting message into database", http.StatusInternalServerError)
		return
	}

	// Store flash message in session
	session.AddFlash("Your message was recorded!")
	session.Save(r, w)

	// Redirect to timeline
	http.Redirect(w, r, "/", http.StatusFound)
}

func main() {
	r := mux.NewRouter()

	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   0, // expires when the broser is closed
		HttpOnly: true,
		Secure:   false, // Must be true in production with HTTPS
	}

	// Register a handler to serve the directory where the static files are (e.g. CSS)
	r.PathPrefix("/assets/").Handler(http.StripPrefix("/assets/", http.FileServer(http.Dir("assets"))))

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
