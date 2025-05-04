package routes

import (
	"api/handlers"
	"api/monitoring"

	"net/http"

	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// SetupRoutes initializes all the application routes
// The routing logic is isolated here
func SetupRoutes(userHandler *handlers.UserHandler, messageHandler *handlers.MessageHandler, systemHandler *handlers.SystemHandler) http.Handler {
	router := mux.NewRouter()

	// User routes
	router.HandleFunc("/login", userHandler.LoginHandler).Methods("POST", "GET")
	router.HandleFunc("/register", userHandler.RegisterHandler).Methods("POST", "GET")
	router.HandleFunc("/fllws/{username}", userHandler.FollowHandler).Methods("GET", "POST")

	// Message routes
	router.HandleFunc("/msgs", messageHandler.GetMessages).Methods("GET")
	router.HandleFunc("/msgs/{username}", messageHandler.MessagesPerUser).Methods("GET", "POST")
	router.HandleFunc("/following/{userID}", messageHandler.UserFollowingHandler).Methods("GET")

	// System routes
	router.HandleFunc("/latest", systemHandler.GetLatest).Methods("GET")

	// Add metrics endpoint
	router.Handle("/metrics", promhttp.Handler()).Methods("GET")

	return monitoring.InstrumentHandler(router)
}
