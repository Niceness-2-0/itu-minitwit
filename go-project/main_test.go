package main

import (
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gorilla/securecookie"
)

// Use the same secret key as your CookieStore
var secretKey = []byte("development-key") // Replace with your actual secret
var s = securecookie.New(secretKey, nil)

/// OBS: If you want to use a test DB you have to inject the db as parameter in the handlers...

// Helper function to perform HTTP requests
func performRequest(req *http.Request, handlerFunc http.HandlerFunc) *httptest.ResponseRecorder {
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(handlerFunc)
	handler.ServeHTTP(rr, req)
	return rr
}

// Helper function to register a user
func registerUser(username, password, password2, email string) *httptest.ResponseRecorder {
	// Create form data
	form := url.Values{}
	form.Add("username", username)
	form.Add("password", password)
	form.Add("password2", password2)
	form.Add("email", email)

	// Create request with form-encoded body
	req, _ := http.NewRequest("POST", "/register", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Perform request and return response
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

// Helper function to logout a user
func logoutUser() *httptest.ResponseRecorder {
	req, _ := http.NewRequest("GET", "/logout", nil)
	return performRequest(req, logoutHandler)
}

func TestRegisterUser(t *testing.T) {
	// Test successful registration
	resp := registerUser("user123", "password123", "password123", "user123@example.com")
	if resp.Code != http.StatusFound {
		t.Errorf("Expected status 302 and success message but got %d. Response: %s", resp.Code, resp.Body.String())
	}

	// Test duplicate username
	resp = registerUser("user123", "password123", "password123", "user123@example.com")
	if resp.Code != http.StatusBadRequest || !strings.Contains(resp.Body.String(), "The username is already taken") {
		t.Errorf("Expected status 400 and duplicate username error but got %d. Response: %s", resp.Code, resp.Body.String())
	}

	// Test empty username
	resp = registerUser("", "password123", "password123", "user2@example.com")
	if resp.Code != http.StatusBadRequest || !strings.Contains(resp.Body.String(), "You have to enter a username") {
		t.Errorf("Expected status 400 and empty username error but got %d. Response: %s", resp.Code, resp.Body.String())
	}

	// Test empty password
	resp = registerUser("user_empty_pw", "", "", "user_empty_pw@example.com")
	if resp.Code != http.StatusBadRequest || !strings.Contains(resp.Body.String(), "You have to enter a password") {
		t.Errorf("Expected status 400 and empty password error but got %d. Response: %s", resp.Code, resp.Body.String())
	}

	// Test mismatching passwords
	resp = registerUser("user_pw_mismatch", "pass1", "pass2", "user_pw_mismatch@example.com")
	if resp.Code != http.StatusBadRequest || !strings.Contains(resp.Body.String(), "The two passwords do not match") {
		t.Errorf("Expected status 400 and mismatched password error but got %d. Response: %s", resp.Code, resp.Body.String())
	}

	// Test invalid email
	resp = registerUser("user_invalid_email", "password123", "password123", "invalid-email")
	if resp.Code != http.StatusBadRequest || !strings.Contains(resp.Body.String(), "You have to enter a valid email address") {
		t.Errorf("Expected status 400 and invalid email error but got %d. Response: %s", resp.Code, resp.Body.String())
	}

}

func TestLoginUser(t *testing.T) {
	// Register a user first
	registerUser("testuser", "password123", "password123", "testuser@example.com")

	// Test successful login
	resp := loginUser("testuser", "password123")
	if resp.Code != http.StatusFound {
		t.Errorf("Expected status 302 (Redirect), got %d", resp.Code)
	}

	// Test empty username
	resp = loginUser("", "password123")
	if resp.Code != http.StatusBadRequest || !strings.Contains(resp.Body.String(), "You have to enter a username") {
		t.Errorf("Expected status 400 and 'You have to enter a username' message but got %d. Response: %s", resp.Code, resp.Body.String())
	}

	// Test empty password
	resp = loginUser("testuser", "")
	if resp.Code != http.StatusBadRequest || !strings.Contains(resp.Body.String(), "You have to enter a password") {
		t.Errorf("Expected status 400 and 'You have to enter a password' message but got %d. Response: %s", resp.Code, resp.Body.String())
	}

	// Test incorrect password
	resp = loginUser("testuser", "wrongpassword")
	if resp.Code != http.StatusUnauthorized || !strings.Contains(resp.Body.String(), "Invalid password") {
		t.Errorf("Expected status 401 for wrong password and 'Invalid password' message but got %d. Response %s", resp.Code, resp.Body.String())
	}

	// Test logout redirection to /
	resp = logoutUser()
	if resp.Code != http.StatusFound {
		t.Errorf("Expected status 302 (Redirect), got %d", resp.Code)
	}
}

func TestAddMessage(t *testing.T) {
	// Register and log in a user
	registerUser("poster", "password123", "password123", "poster@example.com")
	loginResp := loginUser("poster", "password123")

	/*
		In a real browser, the browser automatically sends the session cookie with every subsequent request to the server after login.
		But in this case, in the test environment, we are manually creating requests, which means we must manually attach the session cookie
		to mimic browser behavior.

		Since using a CookieStore, the information about the client's session is all stored in a cookie on the client side and sent
		to the server each time.
		E.g. The client sens the cookie session and the server checks that the `authenticated=true` and
		gives permission to the client to add a message.
	*/

	// Print all cookies from the login response
	cookies := loginResp.Result().Cookies()
	log.Printf("Number of cookies set by the server: %d", len(cookies))

	// Get the cookie from the login response (including all session data for the logged in user)
	var sessionCookie *http.Cookie
	for _, cookie := range cookies {
		// Decode the cookie (from the session ID extract the fields of the session set by the server)
		sessionData := make(map[interface{}]interface{})
		err := s.Decode("session-cookie", cookie.Value, &sessionData)
		if err != nil {
			t.Fatalf("Failed to decode session cookie: %v", err)
		}
		t.Logf("Decoded Session Data: %+v", sessionData)
		if cookie.Name == "session-cookie" {
			sessionCookie = cookie
			break
		}
	}
	if sessionCookie == nil {
		log.Fatal("Session cookie not found!")
	}

	// Send message request
	form := url.Values{}
	form.Add("text", "This is a test message")

	req, _ := http.NewRequest("POST", "/add_message", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Attach session cookie so the server recognizes the logged-in user
	req.AddCookie(sessionCookie)

	resp := performRequest(req, addMessageHandler)

	if resp.Code != http.StatusFound {
		t.Errorf("Expected status 302, got %d. Response body: %s", resp.Code, resp.Body.String())
	}
}
