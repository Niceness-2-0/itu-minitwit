package handlers

import (
	"encoding/json"
	"net/http"
	"os"
	"strconv"
	"time"

	"api/models"
	"api/repositories"

	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
)

type Handler struct {
	userRepo    repositories.UserRepository
	messageRepo repositories.MessageRepository
}

func NewHandler(userRepo repositories.UserRepository, messageRepo repositories.MessageRepository) *Handler {
	return &Handler{
		userRepo:    userRepo,
		messageRepo: messageRepo,
	}
}

func (h *Handler) GetLatest(w http.ResponseWriter, r *http.Request) {
	data, err := os.ReadFile("latest_processed_sim_action_id.txt")
	if err != nil {
		data = []byte("-1")
	}

	latestProcessedID, _ := strconv.Atoi(string(data))
	json.NewEncoder(w).Encode(map[string]int{"latest": latestProcessedID})
}

func (h *Handler) GetMessages(w http.ResponseWriter, r *http.Request) {
	h.updateLatest(r)

	noMsgs := 100
	if noMsgsStr := r.URL.Query().Get("no"); noMsgsStr != "" {
		noMsgs, _ = strconv.Atoi(noMsgsStr)
	}

	messages, err := h.messageRepo.GetLatest(noMsgs)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	response := make([]map[string]interface{}, len(messages))
	for i, msg := range messages {
		response[i] = map[string]interface{}{
			"content":  msg.Content,
			"pub_date": msg.PubDate,
			"user":     msg.User.Username,
		}
	}

	json.NewEncoder(w).Encode(response)
}

func (h *Handler) MessagesPerUser(w http.ResponseWriter, r *http.Request) {
	h.updateLatest(r)
	vars := mux.Vars(r)
	username := vars["username"]

	user, err := h.userRepo.FindByUsername(username)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	if r.Method == http.MethodGet {
		noMsgs := 100
		if noMsgsStr := r.URL.Query().Get("no"); noMsgsStr != "" {
			noMsgs, _ = strconv.Atoi(noMsgsStr)
		}

		messages, err := h.messageRepo.GetByUserID(user.ID, noMsgs)
		if err != nil {
			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		}

		response := make([]map[string]interface{}, len(messages))
		for i, msg := range messages {
			response[i] = map[string]interface{}{
				"content":  msg.Content,
				"pub_date": msg.PubDate,
				"user":     msg.User.Username,
			}
		}
		json.NewEncoder(w).Encode(response)
	} else if r.Method == http.MethodPost {
		var requestData struct{ Content string }
		if err := json.NewDecoder(r.Body).Decode(&requestData); err != nil {
			http.Error(w, `{"status": 400, "error_msg": "Invalid JSON"}`, http.StatusBadRequest)
			return
		}

		message := models.Message{
			Content: requestData.Content,
			PubDate: time.Now().Unix(),
			UserID:  user.ID,
		}
		if err := h.messageRepo.Create(&message); err != nil {
			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

func (h *Handler) Follow(w http.ResponseWriter, r *http.Request) {
	h.updateLatest(r)
	vars := mux.Vars(r)
	username := vars["username"]

	user, err := h.userRepo.FindByUsername(username)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	if r.Method == http.MethodPost {
		var requestData struct {
			Follow   string `json:"follow"`
			Unfollow string `json:"unfollow"`
		}
		if err := json.NewDecoder(r.Body).Decode(&requestData); err != nil {
			http.Error(w, `{"status": 400, "error_msg": "Invalid JSON"}`, http.StatusBadRequest)
			return
		}

		if requestData.Follow != "" {
			followUser, err := h.userRepo.FindByUsername(requestData.Follow)
			if err != nil {
				http.Error(w, "User not found", http.StatusNotFound)
				return
			}
			if err := h.userRepo.Follow(user.ID, followUser.ID); err != nil {
				http.Error(w, "Database error", http.StatusInternalServerError)
				return
			}
		} else if requestData.Unfollow != "" {
			unfollowUser, err := h.userRepo.FindByUsername(requestData.Unfollow)
			if err != nil {
				http.Error(w, "User not found", http.StatusNotFound)
				return
			}
			if err := h.userRepo.Unfollow(user.ID, unfollowUser.ID); err != nil {
				http.Error(w, "Database error", http.StatusInternalServerError)
				return
			}
		}
		w.WriteHeader(http.StatusNoContent)
	} else if r.Method == http.MethodGet {
		followers, err := h.userRepo.GetFollowers(user.ID)
		if err != nil {
			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		}

		followerNames := make([]string, len(followers))
		for i, f := range followers {
			followerNames[i] = f.Username
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"follows": followerNames})
	}
}

func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
	h.updateLatest(r)

	var requestData struct {
		Username string `json:"username"`
		Email    string `json:"email"`
		Password string `json:"pwd"`
	}
	if err := json.NewDecoder(r.Body).Decode(&requestData); err != nil {
		http.Error(w, `{"status": 400, "error_msg": "Invalid JSON"}`, http.StatusBadRequest)
		return
	}

	exists, err := h.userRepo.Exists(requestData.Username)
	if err != nil {
		http.Error(w, `{"status": 500, "error_msg": "Database error"}`, http.StatusInternalServerError)
		return
	}
	if exists {
		http.Error(w, `{"status": 400, "error_msg": "Username taken"}`, http.StatusBadRequest)
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(requestData.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, `{"status": 500, "error_msg": "Error hashing password"}`, http.StatusInternalServerError)
		return
	}

	user := models.User{
		Username: requestData.Username,
		Email:    requestData.Email,
		Password: string(hashedPassword),
	}
	if err := h.userRepo.Create(&user); err != nil {
		http.Error(w, `{"status": 500, "error_msg": "Database error"}`, http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) updateLatest(r *http.Request) {
	if latest := r.URL.Query().Get("latest"); latest != "" {
		os.WriteFile("latest_processed_sim_action_id.txt", []byte(latest), 0644)
	}
}
