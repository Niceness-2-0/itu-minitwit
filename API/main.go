package main

import (
	"log"
	"net/http"
	"os"

	"api/database"
	"api/handlers"
	"api/models"
	"api/repositories"

	"github.com/gorilla/mux"
)

func main() {
	// Initialize database
	db, err := database.New(
		os.Getenv("DB_HOST"),
		os.Getenv("DB_PORT"),
		os.Getenv("DB_USER"),
		os.Getenv("DB_PASSWORD"),
		os.Getenv("DB_NAME"),
	)
	if err != nil {
		log.Fatal("Database connection failed:", err)
	}

	// Auto-migrate models
	if err := db.AutoMigrate(&models.User{}, &models.Message{}, &models.Follower{}); err != nil {
		log.Fatal("Database migration failed:", err)
	}

	// Initialize repositories
	userRepo := repositories.NewUserRepository(db.DB)
	messageRepo := repositories.NewMessageRepository(db.DB)

	// Initialize handler
	handler := handlers.NewHandler(userRepo, messageRepo)

	// Setup routes
	r := mux.NewRouter()
	r.HandleFunc("/latest", handler.GetLatest).Methods("GET")
	r.HandleFunc("/msgs", handler.GetMessages).Methods("GET")
	r.HandleFunc("/msgs/{username}", handler.MessagesPerUser).Methods("GET", "POST")
	r.HandleFunc("/fllws/{username}", handler.Follow).Methods("GET", "POST")
	r.HandleFunc("/register", handler.Register).Methods("POST")

	// Start server
	log.Println("Server running on port 5001")
	http.ListenAndServe(":5001", r)
}
