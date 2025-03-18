package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/joho/godotenv"
	_ "github.com/mattn/go-sqlite3"
)

var API_BASE_URL string

// Configurations
const (
	DATABASE = "../db/minitwit.db"
	PER_PAGE = 30 // Number of messages per page
	SECRET   = "development-key"
)

var (
	store = sessions.NewCookieStore([]byte(SECRET)) // this is stored on the client
)

type User struct {
	ID       uint   `gorm:"primaryKey"`
	Username string `gorm:"uniqueIndex"`
	Email    string
	PwHash   string `json:"pw_hash"`
}

// Message represents a message with user from the database
type Message struct {
	Username string `json:"user"`
	Text     string `json:"content"`
	PubDate  int64  `json:"pub_date"`
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
	var userID string
	if (session.Values["authenticated"] != nil) && (session.Values["authenticated"] != false) {
		loggedIn = true
		userID, _ = session.Values["user_id"].(string)
	}

	if !loggedIn {
		if session.IsNew {
			session.Save(r, w) // send the 'Set-Cookie' header only when the session is first created
		}
		http.Redirect(w, r, "/public", http.StatusFound)
		return
	}

	// Send GET request to API's /following/{userID} endpoint
	resp, err := http.Get(fmt.Sprintf("%s/following/%s", API_BASE_URL, userID))
	if err != nil {
		http.Error(w, "Error fetching data from API", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		http.Error(w, "Failed to fetch timeline data", http.StatusInternalServerError)
		return
	}

	// Parse the JSON response from the API
	var messages []Message
	body, _ := io.ReadAll(resp.Body)
	json.Unmarshal(body, &messages)

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

	resp, err := http.Get(fmt.Sprintf("%s/msgs", API_BASE_URL))
	if err != nil {
		http.Error(w, "Error fetching data from API", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		http.Error(w, "Failed to fetch timeline data", http.StatusInternalServerError)
		return
	}

	// Parse the JSON response from the API
	var messages []Message
	body, _ := io.ReadAll(resp.Body)
	json.Unmarshal(body, &messages)

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

		// Construct the JSON payload for the API request
		payload := map[string]string{
			"username": username,
			"password": password,
		}
		payloadBytes, _ := json.Marshal(payload)

		// Send POST request to API `/login` endpoint
		apiURL := fmt.Sprintf("%s/login", API_BASE_URL)
		resp, err := http.Post(apiURL, "application/json", strings.NewReader(string(payloadBytes)))
		if err != nil {
			http.Error(w, "Error contacting login API", http.StatusInternalServerError)
			return
		}
		defer resp.Body.Close()

		// Handle response in case it a http.Error was returned
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)

			// Treat the body as plain text (since http.Error writes plain text)
			errorMessage := string(body)

			tmpl.ExecuteTemplate(w, "layout.html", map[string]interface{}{
				"Error":    errorMessage,
				"Username": username,
			})
			return
		}

		// Decode successful response
		var responseData map[string]string
		json.NewDecoder(resp.Body).Decode(&responseData)

		// Store the data in the session
		session.Values["authenticated"] = true
		session.Values["user_id"] = responseData["user_id"]
		session.Values["username"] = responseData["username"]

		// Redirect to timeline after successful login
		session.AddFlash("You were logged in")
		session.Save(r, w)

		http.Redirect(w, r, "/", http.StatusFound)

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

		// Construct the JSON payload for the API request
		payload := map[string]string{
			"username": username,
			"email":    email,
			"pwd":      password,
		}
		payloadBytes, _ := json.Marshal(payload)

		// Send POST request to API `/register` endpoint
		apiURL := fmt.Sprintf("%s/register", API_BASE_URL)
		resp, err := http.Post(apiURL, "application/json", strings.NewReader(string(payloadBytes)))
		if err != nil {
			http.Error(w, "Error contacting register API", http.StatusInternalServerError)
			return
		}
		defer resp.Body.Close()

		// Handle response in case it a http.Error was returned
		if resp.StatusCode != http.StatusNoContent {
			body, _ := io.ReadAll(resp.Body)

			// Extract the error message from the JSON response
			var errorResp struct {
				ErrorMsg string `json:"error_msg"`
			}

			if err := json.Unmarshal(body, &errorResp); err != nil {
				// Fallback in case JSON parsing fails
				errorResp.ErrorMsg = "An unknown error occurred"
			}

			tmpl.ExecuteTemplate(w, "layout.html", map[string]interface{}{
				"Error":    errorResp.ErrorMsg,
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
	log.Printf("userTimelineHandler called with path: %s", r.URL.Path)

	vars := mux.Vars(r)
	profileUsername := vars["username"]

	// Send GET request to API's /msgs/{username} endpoint with the Authorization header
	resp, err := http.Get(fmt.Sprintf("%s/msgs/%s", API_BASE_URL, profileUsername))
	if err != nil {
		http.Error(w, "Error fetching data from API", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {

		body, _ := io.ReadAll(resp.Body)
		errorMessage := string(body)
		http.Error(w, errorMessage, http.StatusInternalServerError)
		return
	}

	// Parse the JSON response from the API
	var messages []Message
	body, _ := io.ReadAll(resp.Body)
	json.Unmarshal(body, &messages)

	// Check if the current user is following the profile user
	session, err := store.Get(r, "session-cookie")
	if err != nil {
		http.Error(w, "Unable to retrieve session", http.StatusInternalServerError)
		return
	}

	loggedIn := false
	var loggedInUsername string
	if (session.Values["authenticated"] != nil) && (session.Values["authenticated"] != false) {
		loggedIn = true
		loggedInUsername, _ = session.Values["username"].(string)
	}

	followed := false
	if loggedIn {
		// Send GET request to API's /fllws/{username} endpoint with the Authorization header
		url := fmt.Sprintf("%s/fllws/%s", API_BASE_URL, loggedInUsername)

		// Create a new GET request
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			http.Error(w, "Failed to create request", http.StatusInternalServerError)
			return
		}

		req.Header.Set("Authorization", "Basic c2ltdWxhdG9yOnN1cGVyX3NhZmUh")

		// Send request using http.Client
		client := &http.Client{}
		resp, err = client.Do(req)
		if err != nil {
			http.Error(w, "Error fetching data from API", http.StatusInternalServerError)
			return
		}
		defer resp.Body.Close()

		// Check if API response is successful
		if resp.StatusCode != http.StatusOK {
			http.Error(w, "Failed to retrieve following list", http.StatusInternalServerError)
			return
		}

		// Parse JSON response
		var responseData struct {
			Follows []string `json:"follows"`
		}

		if err := json.NewDecoder(resp.Body).Decode(&responseData); err != nil {
			http.Error(w, "Error decoding response", http.StatusInternalServerError)
			return
		}

		// Check if profileUsername is in the list of follows
		for _, name := range responseData.Follows {
			if name == profileUsername {
				followed = true
				break
			}
		}
	}

	flashes := session.Flashes()
	session.Save(r, w)

	// Define template data
	data := map[string]interface{}{
		"ProfileUser": profileUsername,
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
	var username string
	if (session.Values["authenticated"] != nil) && (session.Values["authenticated"] != false) {
		loggedIn = true
		username, _ = session.Values["username"].(string)
	}

	if !loggedIn {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	vars := mux.Vars(r)
	profileUsername := vars["username"]

	// Send POST request to API `/fllws/{username}` endpoint with the Authorization header
	url := fmt.Sprintf("%s/fllws/%s", API_BASE_URL, username)

	// Construct the JSON payload for the API request
	payload := map[string]string{
		"follow": profileUsername,
	}
	payloadBytes, _ := json.Marshal(payload)
	// Create a new POST request
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(payloadBytes))
	if err != nil {
		http.Error(w, "Error contacting the API", http.StatusInternalServerError)
		return
	}
	req.Header.Set("Authorization", "Basic c2ltdWxhdG9yOnN1cGVyX3NhZmUh")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, "Error sending POST request to API", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	// Handle response in case it a http.Error was returned
	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)

		// Treat the body as plain text (since http.Error writes plain text)
		errorMessage := string(body)

		http.Error(w, errorMessage, http.StatusInternalServerError)
		return
	}

	// Set flash message (as in the Flask version)
	flashMessage := fmt.Sprintf("You are now following \"%s\"", profileUsername)
	session.AddFlash(flashMessage)
	session.Save(r, w)

	// Redirect to user timeline
	http.Redirect(w, r, "/"+profileUsername, http.StatusSeeOther)
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
	var username string
	if (session.Values["authenticated"] != nil) && (session.Values["authenticated"] != false) {
		loggedIn = true
		username, _ = session.Values["username"].(string)
	}

	if !loggedIn {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	vars := mux.Vars(r)
	profileUsername := vars["username"]

	// Send POST request to API `/fllws/{username}` endpoint with the Authorization header
	url := fmt.Sprintf("%s/fllws/%s", API_BASE_URL, username)

	// Construct the JSON payload for the API request
	payload := map[string]string{
		"unfollow": profileUsername,
	}
	payloadBytes, _ := json.Marshal(payload)
	// Create a new POST request
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(payloadBytes))
	if err != nil {
		http.Error(w, "Error contacting the API", http.StatusInternalServerError)
		return
	}
	req.Header.Set("Authorization", "Basic c2ltdWxhdG9yOnN1cGVyX3NhZmUh")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, "Error sending POST request to API", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	// Handle response in case it a http.Error was returned
	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)

		// Treat the body as plain text (since http.Error writes plain text)
		errorMessage := string(body)

		http.Error(w, errorMessage, http.StatusInternalServerError)
		return
	}

	flashMessage := fmt.Sprintf("You are no longer following \"%s\"", profileUsername)
	session.AddFlash(flashMessage)
	session.Save(r, w)

	// Redirect to user timeline
	http.Redirect(w, r, "/"+profileUsername, http.StatusSeeOther)
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
	var username string
	if (session.Values["authenticated"] != nil) && (session.Values["authenticated"] != false) {
		loggedIn = true
		username, _ = session.Values["username"].(string)
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

	// Send POST request to API `/msgs/{username}` endpoint with the Authorization header
	url := fmt.Sprintf("%s/msgs/%s", API_BASE_URL, username)

	// Construct the JSON payload for the API request
	payload := map[string]string{
		"content": text,
	}
	payloadBytes, _ := json.Marshal(payload)
	// Create a new POST request
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(payloadBytes))
	if err != nil {
		http.Error(w, "Error contacting the API", http.StatusInternalServerError)
		return
	}
	req.Header.Set("Authorization", "Basic c2ltdWxhdG9yOnN1cGVyX3NhZmUh")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, "Error sending POST request to API", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	// Handle response in case it a http.Error was returned
	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)

		// Treat the body as plain text (since http.Error writes plain text)
		errorMessage := string(body)

		http.Error(w, errorMessage, http.StatusInternalServerError)
		return
	}
	// Store flash message in session
	session.AddFlash("Your message was recorded!")
	session.Save(r, w)

	// Redirect to timeline
	http.Redirect(w, r, "/", http.StatusFound)
}

func main() {

	if err := godotenv.Load("../.env"); err != nil {
		log.Println("No .env file found, using system environment variables.")
	}

	// Set API_BASE_URL from env
	API_BASE_URL = os.Getenv("API_BASE_URL")
	if API_BASE_URL == "" {
		API_BASE_URL = "http://localhost:5001" // Default fallback
	}

	// Get the PORT environment variable
	port := os.Getenv("PORT")
	if port == "" {
		port = "5000"
	}

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

	log.Println("Server started on port:", port)
	log.Fatal(http.ListenAndServe(":"+port, r))
}
