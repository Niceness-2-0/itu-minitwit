package main

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"regexp"

	"github.com/gorilla/mux"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
    "github.com/gorilla/sessions"
    "time"
)

const DATABASE = "./minitwit.db"
const PER_PAGE = 30 // Number of messages per page

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

// loginHandler handles login requests
func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		http.Error(w, "GET method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var creds struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	// Parse form data
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}
	creds.Username = r.FormValue("username")
	creds.Password = r.FormValue("password")

	db, err := connectDB()
	if err != nil {
		http.Error(w, "Database connection error", http.StatusInternalServerError)
		return
	}
	defer db.Close()

	var user User
	err = db.QueryRow("SELECT user_id, username, pw_hash FROM user WHERE username = ?", creds.Username).Scan(&user.ID, &user.Username, &user.PwHash)
	if err != nil {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PwHash), []byte(creds.Password)); err != nil {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "You were logged in"})
}

// registerHandler handles registration requests
func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		http.Error(w, "GET method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var creds struct {
		Username  string `json:"username"`
		Password  string `json:"password"`
		Password2 string `json:"password2"`
		Email     string `json:"email"`
	}

	// Parse form data
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}
	creds.Username = r.FormValue("username")
	creds.Password = r.FormValue("password")
	creds.Password2 = r.FormValue("password2")
	creds.Email = r.FormValue("email")

	// Validate form data
	if creds.Username == "" {
		http.Error(w, "You have to enter a username", http.StatusBadRequest)
		return
	}
	if creds.Email == "" || !regexp.MustCompile(`^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}$`).MatchString(creds.Email) {
		http.Error(w, "You have to enter a valid email address", http.StatusBadRequest)
		return
	}
	if creds.Password == "" {
		http.Error(w, "You have to enter a password", http.StatusBadRequest)
		return
	}
	if creds.Password != creds.Password2 {
		http.Error(w, "The two passwords do not match", http.StatusBadRequest)
		return
	}

	db, err := connectDB()
	if err != nil {
		http.Error(w, "Database connection error", http.StatusInternalServerError)
		return
	}
	defer db.Close()

	var userID int
	err = db.QueryRow("SELECT user_id FROM user WHERE username = ?", creds.Username).Scan(&userID)
	if err == nil {
		http.Error(w, "The username is already taken", http.StatusBadRequest)
		return
	}

	pwHash, err := bcrypt.GenerateFromPassword([]byte(creds.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Error hashing password", http.StatusInternalServerError)
		return
	}

	_, err = db.Exec("INSERT INTO user (username, email, pw_hash) VALUES (?, ?, ?)", creds.Username, creds.Email, pwHash)
	if err != nil {
		http.Error(w, "Error inserting user into database", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "You were successfully registered and can login now"})
}
var store = sessions.NewCookieStore([]byte("something-very-secret"))

func logoutHandler(w http.ResponseWriter, r *http.Request) {
    session, _ := store.Get(r, "session-name")
    session.Values["user_id"] = nil
    session.Save(r, w)

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]string{"message": "You were logged out"})
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
    userID, ok := session.Values["user_id"].(int)
    if !ok || userID == 0 {
        http.Error(w, "Unauthorized", http.StatusUnauthorized)
        return
    }

    if err := r.ParseForm(); err != nil {
        http.Error(w, "Invalid request payload", http.StatusBadRequest)
        return
    }

    text := r.FormValue("text")
    if text == "" {
        http.Error(w, "Message text is required", http.StatusBadRequest)
        return
    }

    db, err := connectDB()
    if err != nil {
        http.Error(w, "Database connection error", http.StatusInternalServerError)
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
	r.HandleFunc("/public", publicTimelineHandler).Methods("GET")
	r.HandleFunc("/login", loginHandler).Methods("POST")
	r.HandleFunc("/register", registerHandler).Methods("POST")
	r.HandleFunc("/logout", logoutHandler).Methods("GET")
	r.HandleFunc("/", timelineHandler).Methods("GET")
	r.HandleFunc("/{username}", userTimelineHandler).Methods("GET")
	r.HandleFunc("/{username}/follow", followUserHandler).Methods("POST")
	r.HandleFunc("/{username}/unfollow", unfollowUserHandler).Methods("POST")
	r.HandleFunc("/add_message", addMessageHandler).Methods("POST")
	

	log.Println("Server started on :8080")
	log.Fatal(http.ListenAndServe(":8080", r))
}
