package handlers

import (
	"api/models"
	"api/repositories"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type UserHandler struct {
	Repo *repositories.UserRepository
}

type LogEntry struct {
	Timestamp string `json:"timestamp"`
	Level     string `json:"level"`
	Message   string `json:"message"`
	Service   string `json:"service"`
}

func sendLogToLogstash(message string) {
	conn, err := net.Dial("tcp", "localhost:50000") // Change to Logstash container's IP if needed
	if err != nil {
		fmt.Println("Error connecting to Logstash:", err)
		return
	}
	defer conn.Close()

	logEntry := LogEntry{
		Timestamp: time.Now().Format(time.RFC3339),
		Level:     "INFO",
		Message:   message,
		Service:   "go-app",
	}

	jsonLog, _ := json.Marshal(logEntry)

	conn.Write(jsonLog)
	conn.Write([]byte("\n")) // Ensure newline-delimited JSON (NDJSON)
}

func NewUserHandler(repo *repositories.UserRepository) *UserHandler {
	return &UserHandler{Repo: repo}
}
func (h *UserHandler) LoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}
	print("calling loginhandler")
	sendLogToLogstash("LoginHandler called")

	var creds struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	// Fetch user details
	var user models.User
	if err := h.Repo.DB.Where("username = ?", creds.Username).First(&user).Error; err != nil {
		http.Error(w, "Database query error", http.StatusInternalServerError)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PwHash), []byte(creds.Password)); err != nil {
		http.Error(w, "Invalid password", http.StatusUnauthorized)
		return
	}

	response := map[string]string{
		"user_id":  fmt.Sprintf("%d", user.User_Id),
		"username": user.Username,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (h *UserHandler) RegisterHandler(w http.ResponseWriter, r *http.Request) {
	updateLatest(r)

	sendLogToLogstash("RegisterHandler called")

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

	// Check if username exists
	exists, err := h.Repo.UserExists(requestData.Username)
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

	// Create new user
	newUser := models.User{
		Username: requestData.Username,
		Email:    requestData.Email,
		PwHash:   string(hashedPassword),
	}

	if err := h.Repo.CreateUser(&newUser); err != nil {
		http.Error(w, `{"status": 500, "error_msg": "Database error"}`, http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *UserHandler) FollowHandler(w http.ResponseWriter, r *http.Request) {
	updateLatest(r)
	vars := mux.Vars(r)
	username := vars["username"]

	if !notReqFromSimulator(w, r) {
		return
	}

	// Get user ID
	userID, err := h.Repo.GetUserID(username)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			http.Error(w, "User not found", http.StatusNotFound)
		} else {
			http.Error(w, "Database error", http.StatusInternalServerError)
		}
		return
	}

	if r.Method == http.MethodPost {
		var requestData struct {
			FollowUsername   string `json:"follow"`
			UnFollowUsername string `json:"unfollow"`
		}
		if err := json.NewDecoder(r.Body).Decode(&requestData); err != nil {
			http.Error(w, `{"status": 400, "error_msg": "Invalid JSON"}`, http.StatusBadRequest)
			return
		}

		if requestData.FollowUsername != "" {
			// Get the ID of the user to follow
			followID, err := h.Repo.GetUserID(requestData.FollowUsername)
			if err != nil {
				http.Error(w, "User not found", http.StatusNotFound)
				return
			}

			// Follow the user
			if err := h.Repo.FollowUser(userID, followID); err != nil {
				http.Error(w, "Database insert error", http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusNoContent)

		} else if requestData.UnFollowUsername != "" {
			// Get the ID of the user to unfollow
			unfollowID, err := h.Repo.GetUserID(requestData.UnFollowUsername)
			if err != nil {
				http.Error(w, "User not found", http.StatusNotFound)
				return
			}

			// Unfollow the user
			if err := h.Repo.UnfollowUser(userID, unfollowID); err != nil {
				http.Error(w, "Database delete error", http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		}
	} else if r.Method == http.MethodGet {
		noFollowers := 100 // Default limit
		if limitStr := r.URL.Query().Get("no"); limitStr != "" {
			if num, err := strconv.Atoi(limitStr); err == nil {
				noFollowers = num
			}
		}

		followers, err := h.Repo.GetFollowers(userID, noFollowers)
		if err != nil {
			http.Error(w, "Database query error", http.StatusInternalServerError)
			return
		}

		response := map[string][]string{"follows": followers}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}
}
