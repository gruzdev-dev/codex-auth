package http

import (
	"codex-auth/core/ports"
	"fmt"
	"github.com/gorilla/mux"
	"net/http"
)

type Handler struct {
	service ports.UserService
}

func NewHandler(service ports.UserService) *Handler {
	return &Handler{
		service: service,
	}
}

func (h *Handler) RegisterRoutes(router *mux.Router) {
	router.HandleFunc("/", h.HealthCheck).Methods("GET")
}

func (h *Handler) HealthCheck(w http.ResponseWriter, r *http.Request) {
	status := h.service.HealthCheck()
	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, status)
}
