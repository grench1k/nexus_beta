package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"sync"

	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

var (
	clients   = make(map[string]*websocket.Conn)
	clientsMu sync.RWMutex
)

type Message struct {
	Type      string `json:"type"`
	PubKey    string `json:"pubkey,omitempty"`
	Signature string `json:"signature,omitempty"`
	Channel   string `json:"channel,omitempty"`
	Content   string `json:"content,omitempty"`
	Nonce     string `json:"nonce,omitempty"`
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Nexus anonymous server is running"))
	})
	http.HandleFunc("/ws", handleWS)

	log.Printf("Nexus gateway запущен на :%s", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

func handleWS(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("upgrade error:", err)
		return
	}
	defer conn.Close()

	var pubKeyHex string
	authenticated := false

	for {
		_, raw, err := conn.ReadMessage()
		if err != nil {
			break
		}

		var msg Message
		if err := json.Unmarshal(raw, &msg); err != nil {
			continue
		}

		switch msg.Type {

		case "hello":
			nonce := generateNonce()
			conn.WriteJSON(Message{Type: "challenge", Nonce: nonce})

		case "auth":
			pubBytes, err := hex.DecodeString(msg.PubKey)
			if err != nil || len(pubBytes) != ed25519.PublicKeySize {
				conn.WriteJSON(Message{Type: "error", Content: "bad pubkey"})
				continue
			}
			sigBytes, err := hex.DecodeString(msg.Signature)
			if err != nil {
				conn.WriteJSON(Message{Type: "error", Content: "bad signature"})
				continue
			}

			if ed25519.Verify(pubBytes, []byte(msg.Nonce), sigBytes) {
				pubKeyHex = msg.PubKey
				authenticated = true

				clientsMu.Lock()
				clients[pubKeyHex] = conn
				clientsMu.Unlock()

				conn.WriteJSON(Message{Type: "auth_ok", PubKey: pubKeyHex})
				log.Printf("Подключился аноним: %s", pubKeyHex[:16])
			} else {
				conn.WriteJSON(Message{Type: "error", Content: "bad signature"})
			}

		case "message":
			if !authenticated {
				conn.WriteJSON(Message{Type: "error", Content: "not authenticated"})
				continue
			}
			msg.PubKey = pubKeyHex
			broadcast(msg)
		}
	}

	if pubKeyHex != "" {
		clientsMu.Lock()
		delete(clients, pubKeyHex)
		clientsMu.Unlock()
		log.Printf("Отключился аноним: %s", pubKeyHex[:16])
	}
}

func broadcast(msg Message) {
	clientsMu.RLock()
	defer clientsMu.RUnlock()
	for _, c := range clients {
		c.WriteJSON(msg)
	}
}

func generateNonce() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}