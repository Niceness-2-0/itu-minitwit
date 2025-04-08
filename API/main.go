package main

import (
	"api/database"
	"api/handlers"
	"api/repositories"
	"api/routes"
	"log"
	"net/http"
)

func main() {
	// Initialize database
	db, err := database.ConnectDB()
	if err != nil {
		log.Fatal(err)
	}

	// Get sql.DB for connection pool management
	sqlDB, err := db.DB()
	if err != nil {
		log.Fatal("Failed to get database connection:", err)
	}
	defer sqlDB.Close()

	// Initialize repositories
	userRepo := repositories.NewUserRepository(db)
	messageRepo := repositories.NewMessageRepository(db)

	// Initialize handlers
	userHandler := handlers.NewUserHandler(userRepo)
	messageHandler := handlers.NewMessageHandler(messageRepo, userRepo)
	systemHandler := handlers.NewSystemHandler()

	// Setup routes
	router := routes.SetupRoutes(userHandler, messageHandler, systemHandler)

	log.Println("Server started on :5001")
	log.Fatal(http.ListenAndServe(":5001", router))
}
