package main

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/kinyaelgrande/chat-server/rsa"
)

type KeyResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message,omitempty"`
	Keys    rsa.RSAKeys `json:"keys"`
	Error   string      `json:"error,omitempty"`
}

func generateKeysHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

	// Handle preflight OPTIONS request
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		response := KeyResponse{
			Success: false,
			Error:   "Method not allowed. Use GET request.",
		}
		json.NewEncoder(w).Encode(response)
		return
	}

	keys, err := rsa.GenerateKeys()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		response := KeyResponse{
			Success: false,
			Error:   fmt.Sprintf("Error generating keys: %v", err),
		}
		json.NewEncoder(w).Encode(response)
		return
	}

	response := KeyResponse{
		Success: true,
		Message: "RSA keys generated and saved successfully",
		Keys:    keys,
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}
