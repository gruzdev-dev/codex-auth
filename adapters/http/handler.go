package http

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/gruzdev-dev/codex-auth/core/errors"
	"github.com/gruzdev-dev/codex-auth/core/ports"

	"github.com/gorilla/mux"
)

type Handler struct {
	authService   ports.AuthService
	accessService ports.AccessService
}

func NewHandler(authService ports.AuthService, accessService ports.AccessService) *Handler {
	return &Handler{
		authService:   authService,
		accessService: accessService,
	}
}

func (h *Handler) InitRoutes(router *mux.Router) {
	api := router.PathPrefix("/api/v1").Subrouter()

	api.HandleFunc("/register", h.Register).Methods("POST")
	api.HandleFunc("/login", h.Login).Methods("POST")
	api.HandleFunc("/refresh", h.Refresh).Methods("POST")
	api.HandleFunc("/validate", h.Validate).Methods("GET")
}

func (h *Handler) RegisterRoutes(router *mux.Router) {
	h.InitRoutes(router)
}

func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	user, err := h.authService.Register(r.Context(), req.Email, req.Password)
	if err != nil {
		if err == errors.ErrUserAlreadyExists {
			h.writeError(w, http.StatusConflict, err.Error())
			return
		}
		if err == errors.ErrEmailRequired || err == errors.ErrInvalidEmailFormat ||
			err == errors.ErrEmailTooLong || err == errors.ErrPasswordRequired ||
			err == errors.ErrPasswordTooShort || err == errors.ErrPasswordTooLong {
			h.writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		h.writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"id":    user.ID,
		"email": user.Email,
		"role":  user.Role,
	})
}

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	tokenPair, err := h.authService.Login(r.Context(), req.Email, req.Password)
	if err != nil {
		if err == errors.ErrInvalidCredentials {
			h.writeError(w, http.StatusUnauthorized, err.Error())
			return
		}
		h.writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(TokenResponse{
		AccessToken:  tokenPair.AccessToken,
		RefreshToken: tokenPair.RefreshToken,
	})
}

func (h *Handler) Refresh(w http.ResponseWriter, r *http.Request) {
	var req RefreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	tokenPair, err := h.authService.Refresh(r.Context(), req.RefreshToken)
	if err != nil {
		if err == errors.ErrInvalidToken || err == errors.ErrUserNotFound {
			h.writeError(w, http.StatusUnauthorized, err.Error())
			return
		}
		h.writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(TokenResponse{
		AccessToken:  tokenPair.AccessToken,
		RefreshToken: tokenPair.RefreshToken,
	})
}

func (h *Handler) Validate(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	token := parts[1]
	_, err := h.authService.ValidateToken(r.Context(), token)

	if err == nil {
		w.WriteHeader(http.StatusOK)
		return
	}

	err = h.accessService.CheckTmpToken(token)
	if err == nil {
		w.WriteHeader(http.StatusOK)
		return
	}

	h.writeError(w, http.StatusUnauthorized, "invalid token")
}

func (h *Handler) writeError(w http.ResponseWriter, statusCode int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}
