package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"

	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

// Хранилище подключенных клиентов по их публичному ключу
var (
	clients   = make(map[string]*websocket.Conn)
	clientsMu sync.RWMutex
)

// Структура сообщения
type Message struct {
	Type      string `json:"type"`      // "hello", "auth", "message"
	PubKey    string `json:"pubkey"`    // публичный ключ (hex)
	Signature string `json:"signature"` // подпись челленджа (hex)
	Channel   string `json:"channel"`   // ID канала (пока просто строка)
	Content   string `json:"content"`   // текст сообщения
	Nonce     string `json:"nonce"`     // челлендж от сервера
}

func main() {
	http.HandleFunc("/ws", handleWS)
	log.Println("Nexus gateway запущен на :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
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

		// 1. Клиент запрашивает челлендж
		case "hello":
			nonce := generateNonce()
			conn.WriteJSON(Message{Type: "challenge", Nonce: nonce})

		// 2. Клиент присылает подпись челленджа
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

			// В реальности: проверить nonce из Redis (защита от replay)
			// Здесь — упрощенно, проверяем подпись
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

		// 3. Сообщение в канал — рассылаем всем
		case "message":
			if !authenticated {
				conn.WriteJSON(Message{Type: "error", Content: "not authenticated"})
				continue
			}
			broadcast(msg)
		}
	}

	// Отключение
	if pubKeyHex != "" {
		clientsMu.Lock()
		delete(clients, pubKeyHex)
		clientsMu.Unlock()
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
	// В реальности — crypto/rand
	return fmt.Sprintf("nonce-%d", len(clients))
}