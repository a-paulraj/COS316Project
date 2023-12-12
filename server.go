package main

import (
	"fmt"
	"net/http"
	"sync"
	"time"
)

// RateLimiter is a simple rate limiter to prevent flood attacks.
type RateLimiter struct {
	mu      sync.Mutex
	clients map[string]time.Time
}

func (rl *RateLimiter) allowRequest(clientIP string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()

	if rl.clients == nil {
		rl.clients = make(map[string]time.Time)
	}

	if lastRequestTime, ok := rl.clients[clientIP]; ok {
		// If the last request was within the last second, block the request.
		if now.Sub(lastRequestTime) < time.Second {
			return false
		}
	}

	// Allow the request and update the last request time.
	rl.clients[clientIP] = now
	return true
}

func handler(w http.ResponseWriter, r *http.Request) {
	fmt.Println("sup")
	clientIP := r.RemoteAddr
	rl := &RateLimiter{}

	if !rl.allowRequest(clientIP) {
		fmt.Println("yo we out")
		http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	fmt.Fprintf(w, "Hello, %s!", r.URL.Path[1:])
}

func main() {
	http.HandleFunc("/", handler)
	fmt.Println("Server listening on :8080...")
	http.ListenAndServe(":8080", nil)
}
