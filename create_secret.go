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

	// Create a secret
	secret := models.Secret{
		UserID:          3,
		SecretTitle:     "Test Secret",
		SecretContent:   "This is a test secret content",
		ExtractCode:     "123456",
		DestructionMethod: "manual",
		IsDeleted:       false,
	}

	// Insert the secret into the database
	if result := models.DB.Create(&secret); result.Error != nil {
		log.Fatalf("Failed to create secret: %v", result.Error)
	}

	log.Printf("Secret created successfully with ID: %d", secret.ID)
}
