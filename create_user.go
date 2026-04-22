package main

import (
	"log"

	"backend/config"
	"backend/models"
)

func main() {
	// Load configuration
	cfg := config.LoadConfig()

	// Initialize the database
	if err := models.InitDB(cfg); err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}

	// Create a user
	user := models.User{
		Nickname: "Test User",
		Email:    "test@example.com",
		Password: "password123", // In a real application, this would be hashed
		Status:   "active",
		IsDeleted: false,
	}

	// Insert the user into the database
	if result := models.DB.Create(&user); result.Error != nil {
		log.Fatalf("Failed to create user: %v", result.Error)
	}

	log.Printf("User created successfully with ID: %d", user.ID)
}
