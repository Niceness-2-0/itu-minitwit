package handlers

import (
	"api/models"
	"api/monitoring"
	"api/repositories"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type UserHandler struct {
	Repo *repositories.UserRepository
}

func NewUserHandler(repo *repositories.UserRepository) *UserHandler {
	return &UserHandler{Repo: repo}
}
func (h *UserHandler) LoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		monitoring.LoginFailure.WithLabelValues("invalid_json").Inc()

		return
	}

	var creds struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		monitoring.LoginFailure.WithLabelValues("invalid_json").Inc()
		logrus.WithFields(logrus.Fields{
			"handler":  "LoginHandler",
			"username": creds.Username,
			"error":    "invalid JSON",
		}).Warn("Login failed")

		return
	}

	var user models.User
	if err := h.Repo.DB.Where("username = ?", creds.Username).First(&user).Error; err != nil {
		http.Error(w, "Database query error", http.StatusInternalServerError)
		monitoring.LoginFailure.WithLabelValues("db_error").Inc()

		logrus.WithFields(logrus.Fields{
			"handler":  "LoginHandler",
			"username": creds.Username,
			"error":    "database error",
		}).Warn("Login failed")

		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PwHash), []byte(creds.Password)); err != nil {
		http.Error(w, "Invalid password", http.StatusUnauthorized)
		monitoring.LoginFailure.WithLabelValues("invalid_password").Inc()
		logrus.WithFields(logrus.Fields{
			"handler":  "LoginHandler",
			"username": creds.Username,
			"error":    "invalid password",
		}).Warn("Login failed")
		return
	}

	monitoring.LoginSuccess.Inc()

	response := map[string]string{
		"user_id":  fmt.Sprintf("%d", user.User_Id),
		"username": user.Username,
	}
	monitoring.LoginSuccess.Inc()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (h *UserHandler) RegisterHandler(w http.ResponseWriter, r *http.Request) {
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
		monitoring.RegisterFailure.WithLabelValues("invalid_json").Inc()
		monitoring.RegisterFailure.WithLabelValues("invalid_json").Inc()
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
		monitoring.RegisterFailure.WithLabelValues("db_error_registration").Inc()
		monitoring.RegisterFailure.WithLabelValues("db_error_registration").Inc()
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
		monitoring.RegisterFailure.WithLabelValues("failed_registration").Inc()
		monitoring.RegisterFailure.WithLabelValues("failed_registration").Inc()
		return
	}

	w.WriteHeader(http.StatusNoContent)
	monitoring.RegisterSuccess.Inc()
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
