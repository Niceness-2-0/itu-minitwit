package main

import (
	
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

func setupTestDB() (*sql.DB, error) {
	// Use an in-memory SQLite database for testing
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		return nil, err
	}

	// Create tables (copy schema from minitwit.db)
	schema := `
	CREATE TABLE user (
		user_id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT NOT NULL UNIQUE,
		email TEXT NOT NULL,
		pw_hash TEXT NOT NULL
	);
	CREATE TABLE message (
		message_id INTEGER PRIMARY KEY AUTOINCREMENT,
		author_id INTEGER NOT NULL,
		text TEXT NOT NULL,
		pub_date INTEGER NOT NULL,
		flagged INTEGER DEFAULT 0
	);
	CREATE TABLE follower (
		who_id INTEGER NOT NULL,
		whom_id INTEGER NOT NULL
	);
	`
	_, err = db.Exec(schema)
	return db, err
}

// Helper function to perform HTTP requests
func performRequest(req *http.Request, handlerFunc http.HandlerFunc) *httptest.ResponseRecorder {
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(handlerFunc)
	handler.ServeHTTP(rr, req)
	return rr
}

// Helper function to register a user
func registerUser(username, password, email string) *httptest.ResponseRecorder {
	form := url.Values{}
	form.Add("username", username)
	form.Add("password", password)
	form.Add("password2", password)
	form.Add("email", email)

	req, _ := http.NewRequest("POST", "/register", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return performRequest(req, registerHandler)
}

// Helper function to login a user
func loginUser(username, password string) *httptest.ResponseRecorder {
	form := url.Values{}
	form.Add("username", username)
	form.Add("password", password)

	req, _ := http.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return performRequest(req, loginHandler)
}

func TestRegisterUser(t *testing.T) {
	db, err := setupTestDB()
	if err != nil {
		t.Fatalf("Failed to set up test database: %v", err)
	}
	defer db.Close()

	// Test successful registration
	resp := registerUser("user1", "password123", "user1@example.com")
	if resp.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.Code)
	}

	// Test duplicate username
	resp = registerUser("user1", "password123", "user1@example.com")
	if resp.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400 for duplicate username, got %d", resp.Code)
	}

	// Test empty username
	resp = registerUser("", "password123", "user2@example.com")
	if resp.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400 for empty username, got %d", resp.Code)
	}

	// Test invalid email
	resp = registerUser("user3", "password123", "invalid-email")
	if resp.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400 for invalid email, got %d", resp.Code)
	}
}

func TestLoginUser(t *testing.T) {
	db, err := setupTestDB()
	if err != nil {
		t.Fatalf("Failed to set up test database: %v", err)
	}
	defer db.Close()

	// Register a user first
	registerUser("testuser", "password123", "testuser@example.com")

	// Test successful login
	resp := loginUser("testuser", "password123")
	if resp.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.Code)
	}

	// Test incorrect password
	resp = loginUser("testuser", "wrongpassword")
	if resp.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401 for wrong password, got %d", resp.Code)
	}

	// Test non-existent user
	resp = loginUser("nonexistent", "password123")
	if resp.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401 for non-existent user, got %d", resp.Code)
	}
}

func TestAddMessage(t *testing.T) {
	db, err := setupTestDB()
	if err != nil {
		t.Fatalf("Failed to set up test database: %v", err)
	}
	defer db.Close()

	// Register and log in a user
	registerUser("poster", "password123", "poster@example.com")
	loginResp := loginUser("poster", "password123")

	// Extract session cookie
	sessionCookie := loginResp.Result().Cookies()

	// Send message request
	form := url.Values{}
	form.Add("text", "This is a test message")

	req, _ := http.NewRequest("POST", "/add_message", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Attach session cookie
	for _, cookie := range sessionCookie {
		req.AddCookie(cookie)
	}

	resp := performRequest(req, addMessageHandler)

	if resp.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.Code)
	}

	// Check response message
	var jsonResponse map[string]string
	json.NewDecoder(resp.Body).Decode(&jsonResponse)
	if jsonResponse["message"] != "Your message was recorded" {
		t.Errorf("Expected confirmation message, got: %s", jsonResponse["message"])
	}
}
