package main

import (
	"api/database"
	"api/handlers"
	"api/logger"
	"api/repositories"
	"api/routes"
	"net/http"

	"github.com/sirupsen/logrus"
)

func main() {
	// Set up logrus to write logs to a file
	logger.InitLogger()

	logrus.Info("Initializing application")

	// Initialize database
	db, err := database.ConnectDB()
	if err != nil {
		logrus.Fatalf("Database connection failed: %v", err)
	}

	sqlDB, err := db.DB()
	if err != nil {
		logrus.Fatalf("Failed to get database connection: %v", err)
	}
	defer sqlDB.Close()

	logrus.Info("Database connected")

	// Initialize repositories and handlers
	userRepo := repositories.NewUserRepository(db)
	messageRepo := repositories.NewMessageRepository(db)

	userHandler := handlers.NewUserHandler(userRepo)
	messageHandler := handlers.NewMessageHandler(messageRepo, userRepo)
	systemHandler := handlers.NewSystemHandler()

	logrus.Info("Repositories and handlers initialized")

	// Setup routes
	router := routes.SetupRoutes(userHandler, messageHandler, systemHandler)

	logrus.WithField("port", "5001").Info("Starting HTTP server")
	if err := http.ListenAndServe(":5001", router); err != nil {
		logrus.Fatalf("Server failed: %v", err)
	}
}
