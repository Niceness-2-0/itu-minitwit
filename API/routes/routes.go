package routes

import (
	"api/handlers"

	"github.com/gorilla/mux"
)

// SetupRoutes initializes all the application routes
// The routing logic is isolated here
func SetupRoutes(userHandler *handlers.UserHandler, messageHandler *handlers.MessageHandler, systemHandler *handlers.SystemHandler) *mux.Router {
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

	return router
}
