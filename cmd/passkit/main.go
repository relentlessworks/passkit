package main

import (
	"log"

	"github.com/relentlessworks/passkit/internal/passkit"
)

func main() {
	cfg := passkit.ParseFlags()
	log.Printf("passkit starting — %s", cfg)
	srv := passkit.New(cfg)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
