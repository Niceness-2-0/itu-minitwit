package handlers

import (
	"api/models"
	"api/monitoring"
	"api/repositories"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/mux"
	"gorm.io/gorm"
)

// MessageHandler handles message-related endpoints
type MessageHandler struct {
	MessageRepo *repositories.MessageRepository
	UserRepo    *repositories.UserRepository
}

// NewMessageHandler initializes a new MessageHandler
func NewMessageHandler(msgRepo *repositories.MessageRepository, userRepo *repositories.UserRepository) *MessageHandler {
	return &MessageHandler{MessageRepo: msgRepo, UserRepo: userRepo}
}

// GetMessages retrieves the latest messages
func (h *MessageHandler) GetMessages(w http.ResponseWriter, r *http.Request) {
	updateLatest(r)

	noMsgs := 100 // Default to 100 messages
	if noMsgsStr := r.URL.Query().Get("no"); noMsgsStr != "" {
		if num, err := strconv.Atoi(noMsgsStr); err == nil {
			noMsgs = num
		}
	}

	// Fetch messages from repository
	messages, err := h.MessageRepo.GetMessages(noMsgs)
	if err != nil {
		http.Error(w, "Error fetching messages", http.StatusInternalServerError)
		monitoring.MessageFetchFailure.WithLabelValues("failed to fecth all messages").Inc()
		monitoring.MessageFetchFailure.WithLabelValues("failed to fecth all messages").Inc()
		return
	}

	// Send JSON response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(messages)
}

func (h *MessageHandler) MessagesPerUser(w http.ResponseWriter, r *http.Request) {
	updateLatest(r)
	vars := mux.Vars(r)
	username := vars["username"]

	noMsgs := 100 // Default 100 messages
	if noMsgsStr := r.URL.Query().Get("no"); noMsgsStr != "" {
		if num, err := strconv.Atoi(noMsgsStr); err == nil {
			noMsgs = num
		}
	}

	// Get user ID
	userID, err := h.UserRepo.GetUserID(username)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			http.Error(w, "User not found", http.StatusNotFound)
		} else {
			http.Error(w, "Database error", http.StatusInternalServerError)
		}
		return
	}
	if r.Method == http.MethodGet {

		// Fetch messages for the user
		messages, err := h.MessageRepo.GetMessagesPerUser(noMsgs, userID)
		if err != nil {
			http.Error(w, "Error fetching messages", http.StatusInternalServerError)
			monitoring.MessageFetchFailure.WithLabelValues("failure on fetching messages per user").Inc()
			return
		}
		// Send JSON response
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(messages)

	} else if r.Method == http.MethodPost {
		if !notReqFromSimulator(w, r) {
			return
		}

		// Decode request body
		var requestData struct {
			Content string `json:"content"`
		}
		if err := json.NewDecoder(r.Body).Decode(&requestData); err != nil {
			http.Error(w, `{"status": 400, "error_msg": "Invalid JSON"}`, http.StatusBadRequest)
			monitoring.MessagePostFailure.WithLabelValues("failed to post messsage - invalid json").Inc()
			monitoring.MessagePostFailure.WithLabelValues("failed to post messsage - invalid json").Inc()
			return
		}

		// Create Message instance
		message := &models.Message{
			AuthorID: uint(userID), // Convert userID from int to uint
			Content:  requestData.Content,
			PubDate:  time.Now().Unix(),
			Flagged:  0,
		}

		// Save message using repository
		h.MessageRepo.SaveMessage(message)
		monitoring.MessagesPosted.Inc()
		w.WriteHeader(http.StatusNoContent)
	}

}

// userFollowing hanldes GET (retrieve messages from the people the user follows)
func (h *MessageHandler) UserFollowingHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userIDStr := vars["userID"]

	userID, err := strconv.Atoi(userIDStr)
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	// Parse query parameters
	noMsgs := 100 // Default message limit
	if noMsgsStr := r.URL.Query().Get("no"); noMsgsStr != "" {
		if num, err := strconv.Atoi(noMsgsStr); err == nil {
			noMsgs = num
		}
	}

	offset := 0
	if offsetStr := r.URL.Query().Get("offset"); offsetStr != "" {
		if num, err := strconv.Atoi(offsetStr); err == nil {
			offset = num
		}
	}

	// Retrieve messages from repository
	messages, err := h.MessageRepo.GetFollowingMessages(uint(userID), noMsgs, offset)
	if err != nil {
		http.Error(w, "Database query error", http.StatusInternalServerError)
		return
	}

	// Send JSON response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(messages)
}
