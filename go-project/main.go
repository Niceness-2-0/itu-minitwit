package main

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"os"

	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	_ "github.com/mattn/go-sqlite3"
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

func main() {

	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using system environment variables.")
	}

	// Get the PORT environment variable
	port := os.Getenv("PORT")
	if port == "" {
		port = "5000" // Default if PORT is not set
	}

	r := mux.NewRouter()
	r.HandleFunc("/public", publicTimelineHandler).Methods("GET")

	log.Println("Server started on port:", port)
	log.Fatal(http.ListenAndServe(":"+port, r))
}
