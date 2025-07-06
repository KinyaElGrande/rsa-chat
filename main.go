package main

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/gorilla/websocket"
)

type Message struct {
	Type      string    `json:"type"`
	ID        int64     `json:"id"`
	Data      string    `json:"data"`
	PublicKey string    `json:"publicKey,omitempty" `
	From      string    `json:"from"`
	Timestamp time.Time `json:"timestamp"`
}

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

var clients = make(map[*websocket.Conn]bool)
var broadcast = make(chan []byte)

var authTokens = map[string]string{
	"eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFMSUNFIiwiYWRtaW4iOnRydWUsImlhdCI6MTc1MTgxMzMxMywiZXhwIjoxNzUxODE2OTEzfQ": "Alice",
	"eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkJPQiIsImFkbWluIjp0cnVlLCJpYXQiOjE3NTE4MTMzMTMsImV4cCI6MTc1MTgxNjkxM30":    "Bob",
}

func handleConnections(w http.ResponseWriter, r *http.Request) {
	// Get token from header or query
	token := r.Header.Get("Authorization")
	if token == "" {
		token = r.URL.Query().Get("token")
	}

	// handle simple authentication
	if token == "" {
		http.Error(w, "Missing token", http.StatusUnauthorized)
		return
	}

	// handle token authentication
	client, ok := authTokens[token]
	if !ok {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	clients[conn] = true
	log.Printf("%s has connected. Total: %d", client, len(clients))

	for {
		_, msg, err := conn.ReadMessage()
		if err != nil {
			log.Printf("error reading the message: %v", err)
			delete(clients, conn)
			break
		}

		var message Message
		if err := json.Unmarshal(msg, &message); err == nil {
			switch message.Type {
			case "key-gen":
				keys, err := GenerateKeys()
				if err != nil {
					log.Printf("error generating keys: %v", err)
					continue
				}

				privateKey := keys["private"]
				publicKey := keys["public"]

				privateResponse := Message{
					ID:   time.Now().Unix(),
					Type: "private-key",
					Data: privateKey,
				}

				privateMsg, _ := json.Marshal(privateResponse)
				conn.WriteMessage(websocket.TextMessage, privateMsg)

				publicResponse := Message{
					ID:   time.Now().Unix(),
					Type: "public-key",
					Data: publicKey,
				}

				publicMsg, _ := json.Marshal(publicResponse)

				broadcast <- publicMsg
			case "message":
				// get the public key from the message
				// publicKey := message.PublicKey

				// handle the encryption of the messsage using the Public key
				msg := Message{
					ID:   time.Now().Unix(),
					Type: "message",
					Data: message.Data,
				}

				responseData, _ := json.Marshal(msg)

				broadcast <- responseData
			}

		}

		broadcast <- msg
	}
}

func handleMessages() {
	for {
		msg := <-broadcast
		for client := range clients {
			err := client.WriteMessage(websocket.TextMessage, msg)
			if err != nil {
				log.Printf("error writing the message: %v", err)
				client.Close()
				delete(clients, client)
			}
		}
	}
}

func main() {
	http.HandleFunc("/ws", handleConnections)
	go handleMessages()

	log.Println("Server starting on :8080")
	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}
