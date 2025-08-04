package main

import (
	"log"
	"net/http"
)

func main() {
	http.HandleFunc("/generate-keys", generateKeysHandler)
	http.HandleFunc("/ws", handleConnections)
	go handleMessages()

	log.Println("Server starting on :8080")
	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}
