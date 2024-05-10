package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"
)

func main() {
	// Define the port to listen on
	port := "8080"
	if len(os.Args) > 1 {
		port = os.Args[1]
	}

	// Define the HTTP server handler
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		currentTime := time.Now()
		response := fmt.Sprintf("Port: %v\nMethod: %s\nURI: %s\nTime: %s", port, r.Method, r.RequestURI, currentTime.Format(time.RFC3339))
		_, err := fmt.Fprintln(w, response)
		if err != nil {
			log.Fatal(err)
		}
	})

	// Start the HTTP server
	log.Printf("Server starting on port %s", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatalf("Error starting server: %s", err)
	}
}
