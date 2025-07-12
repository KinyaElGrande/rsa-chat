package main

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/gorilla/websocket"
	"github.com/kinyaelgrande/chat-server/aes"
	"github.com/kinyaelgrande/chat-server/rsa"
)

type (
	Message struct {
		Type      string    `json:"type"`
		ID        int64     `json:"id"`
		Data      string    `json:"data"`
		Key       string    `json:"key,omitempty"`
		PublicKey string    `json:"publicKey,omitempty"`
		From      string    `json:"from"`
		Timestamp time.Time `json:"timestamp"`
	}

	Client struct {
		conn *websocket.Conn
		id   string
	}

	BroadcastMessage struct {
		client  *Client
		message []byte
	}
)

var (
	upgrader = websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			return true
		},
	}

	clients   = make(map[*Client]bool)
	broadcast = make(chan BroadcastMessage)

	// authentication data for Alice and Bob
	authTokens = map[string]string{
		"eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFMSUNFIiwiYWRtaW4iOnRydWUsImlhdCI6MTc1MTgxMzMxMywiZXhwIjoxNzUxODE2OTEzfQ": "Alice",
		"eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkJPQiIsImFkbWluIjp0cnVlLCJpYXQiOjE3NTE4MTMzMTMsImV4cCI6MTc1MTgxNjkxM30":    "Bob",
	}
)

func handleConnections(w http.ResponseWriter, r *http.Request) {
	// Get token from header or query
	token := r.Header.Get("Authorization")
	if token == "" {
		token = r.URL.Query().Get("token")
	}

	// handle simple authentication
	if token == "" {
		http.Error(w, "Authentication failed: missing token", http.StatusUnauthorized)
		return
	}

	// handle token authentication
	username, ok := authTokens[token]
	if !ok {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	// Create client instance
	client := &Client{
		conn: conn,
		id:   username,
	}

	// Add client to clients map
	clients[client] = true
	log.Printf("%s has connected. Total: %d", username, len(clients))

	for {
		_, msg, err := conn.ReadMessage()
		if err != nil {
			log.Printf("error reading the message: %v", err)
			delete(clients, client)
			break
		}

		var message Message
		if err := json.Unmarshal(msg, &message); err == nil {
			switch message.Type {
			case "keys-exchange":
				msg := Message{
					Type:      "keys-exchange",
					PublicKey: message.PublicKey,
					From:      username,
				}

				responseData, _ := json.Marshal(msg)

				broadcastMsg := BroadcastMessage{
					client:  client,
					message: responseData,
				}

				broadcast <- broadcastMsg
			case "message":
				messageId := time.Now().Unix()
				privateMessage := Message{
					ID:   messageId,
					Type: "message",
					Data: message.Data,
				}

				privateMsg, _ := json.Marshal(privateMessage)
				client.conn.WriteMessage(websocket.TextMessage, privateMsg)

				// get the public key from the message
				// encrypt the AES secret key using the public key
				// encrypt the message using the AES secret key
				pubKey := message.PublicKey
				if pubKey == "" {
					log.Printf("error: public key is empty")
					continue
				}

				aesSecretKey, err := aes.GenerateKey()
				if err != nil {
					log.Printf("error generating AES secret key: %v", err)
					continue
				}

				aesCrypto := aes.NewAESCrypto(aesSecretKey)

				encryptedKey, err := rsa.Encrypt(pubKey, aesSecretKey)
				if err != nil {
					log.Printf("error encrypting AES secret key: %v", err)
					continue
				}

				messageCipher, err := aesCrypto.Encrypt(message.Data)
				if err != nil {
					log.Printf("error encrypting message: %v", err)
					continue
				}

				msg := Message{
					ID:   messageId,
					Type: "message",
					Data: string(messageCipher),
					Key:  string(encryptedKey),
					From: username,
				}

				responseData, _ := json.Marshal(msg)

				broadcastMsg := BroadcastMessage{
					client:  client,
					message: responseData,
				}

				broadcast <- broadcastMsg
			}

		}
	}
}

func handleMessages() {
	for {
		broadcasted := <-broadcast

		for client := range clients {
			if client == broadcasted.client {
				continue
			}

			err := client.conn.WriteMessage(websocket.TextMessage, broadcasted.message)
			if err != nil {
				log.Printf("error writing the message: %v", err)
				client.conn.Close()
				delete(clients, client)
			}
		}
	}
}
