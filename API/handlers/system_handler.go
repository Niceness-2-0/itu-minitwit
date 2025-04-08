package handlers

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
)

// SystemHandler handles system-related endpoints
type SystemHandler struct{}

// NewSystemHandler creates a new SystemHandler
func NewSystemHandler() *SystemHandler {
	return &SystemHandler{}
}

// GetLatest reads the latest processed command ID from a file and returns it as JSON
func (h *SystemHandler) GetLatest(w http.ResponseWriter, r *http.Request) {
	data, err := os.ReadFile("../db/latest_processed_sim_action_id.txt")
	if err != nil {
		// If the file doesn't exist or there's an error reading, default to -1
		log.Println(fmt.Errorf("error reading latest ID file: %w", err))
		data = []byte("-1")
	}

	latestProcessedID, err := strconv.Atoi(string(data))
	if err != nil {
		latestProcessedID = -1
	}

	response := map[string]int{"latest": latestProcessedID}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func updateLatest(r *http.Request) {
	latest := r.URL.Query().Get("latest")
	if latest == "" {
		return
	}

	parsedCommandID, err := strconv.Atoi(latest)
	if err != nil || parsedCommandID == -1 {
		return
	}

	err = os.WriteFile("../db/latest_processed_sim_action_id.txt", []byte(strconv.Itoa(parsedCommandID)), 0644)
	if err != nil {
		fmt.Println("Error writing latest ID:", err)
	}
}

// notReqFromSimulator checks if the request is authorized
func notReqFromSimulator(w http.ResponseWriter, r *http.Request) bool {
	fromSimulator := r.Header.Get("Authorization")

	// Expected authorization header value
	expectedAuth := os.Getenv("AUTH_HEADER")

	if fromSimulator != expectedAuth {
		http.Error(w, `{"status": 400, "error_msg": "You are not authorized to use this resource!"}`, http.StatusForbidden)
		return false
	}

	return true
}
