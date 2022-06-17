package handlers

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
)

type check struct {
	log *log.Logger
}

func (c check) readiness(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	status := struct {
		Status string
	}{
		Status: "OK",
	}
	log.Println(r, status)
	return json.NewEncoder(w).Encode(status)
}
