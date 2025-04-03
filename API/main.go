package main

import (
	"api/handlers"
	"api/repositories"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"github.com/joho/godotenv"
	_ "github.com/lib/pq" // PostgreSQL driver

	"github.com/gorilla/mux"
)

var (
	host     string
	port     int
	user     string
	password string
	dbname   string
	schema   string
)

// The init() function is a special function in Go that is automatically called before main()
func init() {
	// Load environment variables from .env file
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	// Set the schema name from the environment variable
	schema = os.Getenv("SCHEMA_NAME")
	host = os.Getenv("DB_HOST")
	port, _ = strconv.Atoi(os.Getenv("DB_PORT"))
	user = os.Getenv("DB_USER")
	password = os.Getenv("DB_PASSWORD")
	dbname = os.Getenv("DB_NAME")
}

func main() {
	// Database connection string
	psqlInfo := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=require",
		host, port, user, password, dbname)

	// Open DB connection
	db, err := gorm.Open(postgres.Open(psqlInfo), &gorm.Config{})
	if err != nil {
		log.Fatal("Error opening database:", err)
	}

	// Get sql.DB to manage connection pool
	sqlDB, err := db.DB()
	if err != nil {
		log.Fatal("Failed to get database connection:", err)
	}
	defer sqlDB.Close() // Ensure the connection is closed on shutdown

	// Initialize repositories
	userRepo := repositories.NewUserRepository(db)
	messageRepo := repositories.NewMessageRepository(db)

	// Initialize handlers
	userHandler := handlers.NewUserHandler(userRepo)
	messageHandler := handlers.NewMessageHandler(messageRepo, userRepo)
	systemHandler := handlers.NewSystemHandler()

	// Set up router
	router := mux.NewRouter()
	router.HandleFunc("/login", userHandler.LoginHandler).Methods("POST", "GET")
	router.HandleFunc("/register", userHandler.RegisterHandler).Methods("POST", "GET")
	router.HandleFunc("/latest", systemHandler.GetLatest).Methods("GET")
	router.HandleFunc("/msgs", messageHandler.GetMessages).Methods("GET")
	router.HandleFunc("/msgs/{username}", messageHandler.MessagesPerUser).Methods("GET", "POST")
	router.HandleFunc("/fllws/{username}", userHandler.FollowHandler).Methods("GET", "POST")
	router.HandleFunc("/following/{userID}", messageHandler.UserFollowingHandler).Methods("GET")

	log.Println("Server started on :5001")
	log.Fatal(http.ListenAndServe(":5001", router))
}
