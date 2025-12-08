//go:build integration

package bdd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"time"

	"github.com/cucumber/godog"
	"github.com/gorilla/mux"

	"codex-auth/adapters/hasher"
	authHttp "codex-auth/adapters/http"
	"codex-auth/adapters/storage/postgres"
	"codex-auth/adapters/token"
	"codex-auth/core/service"
)

const (
	secret   = "test-secret"
	tokenTTL = 5 * time.Second
)

type authTestState struct {
	router           *mux.Router
	lastResponse     *httptest.ResponseRecorder
	lastAccessToken  string
	lastRefreshToken string
	firstAccessToken string
	firstRefreshToken string
}

func newAuthTestState() *authTestState {
	repo := postgres.NewUserRepo(dbPool)
	hash := hasher.NewBcryptHasher()
	tokenManager := token.NewJWTManager(secret, tokenTTL)

	svc := service.NewUserService(repo, hash, tokenManager)
	handler := authHttp.NewHandler(svc)

	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	return &authTestState{
		router: router,
	}
}

func (t *authTestState) serviceIsRunning() error {
	if t.router == nil {
		return fmt.Errorf("http router is not initialized")
	}
	return nil
}

func (t *authTestState) dbIsClean() error {
	_, err := dbPool.Exec(context.Background(), "TRUNCATE TABLE users")
	return err
}

func (t *authTestState) noUserWithEmail(ctx context.Context, email string) error {
	var count int
	err := dbPool.QueryRow(ctx, "SELECT COUNT(*) FROM users WHERE email = $1", email).Scan(&count)
	if err != nil {
		return err
	}

	if count > 0 {
		return fmt.Errorf("user with email %s exists", email)
	}
	return nil
}

func (t *authTestState) iRegisterUser(ctx context.Context, email, password string) error {
	reqBody := authHttp.RegisterRequest{
		Email:    email,
		Password: password,
	}
	bodyBytes, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/register", bytes.NewBuffer(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	t.router.ServeHTTP(rr, req)

	t.lastResponse = rr
	return nil
}

func (t *authTestState) registrationShouldBeSuccess(ctx context.Context) error {
	if t.lastResponse.Code != http.StatusCreated {
		return fmt.Errorf("expected status 201 Created, got %d. Body: %s", t.lastResponse.Code, t.lastResponse.Body.String())
	}
	return nil
}

func (t *authTestState) iLoginUser(ctx context.Context, email, password string) error {
	reqBody := authHttp.LoginRequest{
		Email:    email,
		Password: password,
	}
	bodyBytes, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/login", bytes.NewBuffer(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	t.router.ServeHTTP(rr, req)

	t.lastResponse = rr
	return nil
}

func (t *authTestState) iShouldGetTokenPair(ctx context.Context) error {
	if t.lastResponse.Code != http.StatusOK {
		return fmt.Errorf("expected status 200 OK, got %d. Body: %s", t.lastResponse.Code, t.lastResponse.Body.String())
	}

	var resp authHttp.TokenResponse
	if err := json.Unmarshal(t.lastResponse.Body.Bytes(), &resp); err != nil {
		return fmt.Errorf("failed to decode response body: %w", err)
	}

	if resp.AccessToken == "" {
		return fmt.Errorf("access token is empty")
	}

	if resp.RefreshToken == "" {
		return fmt.Errorf("refresh token is empty")
	}

	t.lastAccessToken = resp.AccessToken
	t.lastRefreshToken = resp.RefreshToken

	return nil
}

func (t *authTestState) iAccessProtectedResource(ctx context.Context) error {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/validate", nil)
	req.Header.Set("Authorization", "Bearer "+t.lastAccessToken)
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	t.router.ServeHTTP(rr, req)

	t.lastResponse = rr
	return nil
}

func (t *authTestState) accessShouldBeAllowed(ctx context.Context) error {
	if t.lastResponse.Code != http.StatusOK {
		return fmt.Errorf("expected status 200 OK, got %d. Body: %s", t.lastResponse.Code, t.lastResponse.Body.String())
	}
	return nil
}

func (t *authTestState) userIdShouldNotBeEmpty(ctx context.Context) error {
	userID := t.lastResponse.Header().Get("X-User-Id")
	if userID == "" {
		return fmt.Errorf("X-User-Id header is empty")
	}
	return nil
}

func (t *authTestState) iRefreshTokens(ctx context.Context) error {
	reqBody := authHttp.RefreshRequest{
		RefreshToken: t.lastRefreshToken,
	}
	bodyBytes, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/refresh", bytes.NewBuffer(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	t.router.ServeHTTP(rr, req)

	t.lastResponse = rr
	t.firstAccessToken = t.lastAccessToken
	t.firstRefreshToken = t.lastRefreshToken

	return nil
}

func (t *authTestState) newTokensShouldBeDifferent(ctx context.Context) error {
	if t.lastAccessToken == t.firstAccessToken {
		return fmt.Errorf("new access token is identical to old one")
	}

	if t.lastRefreshToken == t.firstRefreshToken {
		return fmt.Errorf("new refresh token is identical to old one")
	}

	return nil
}

func (t *authTestState) oldAccessTokenShouldBeInvalid(ctx context.Context, ttl string) error {

	ttlInt, err := strconv.Atoi(ttl)
	if err != nil {
		return fmt.Errorf("failed to convert ttl to int: %w", err)
	}
	
	time.Sleep(time.Duration(ttlInt) * time.Second)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/validate", nil)
	req.Header.Set("Authorization", "Bearer "+t.firstAccessToken)
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	t.router.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		return fmt.Errorf("expected status 401 Unauthorized, got %d. Body: %s", rr.Code, rr.Body.String())
	}
	return nil
}

func InitializeAuthScenario(ctx *godog.ScenarioContext) {
	state := newAuthTestState()

	ctx.Step(`^сервис аутентификации запущен$`, state.serviceIsRunning)
	ctx.Step(`^база данных очищена$`, state.dbIsClean)
	ctx.Step(`^в системе нет пользователя "([^"]*)"$`, state.noUserWithEmail)
	ctx.Step(`^пользователь регистрируется с email "([^"]*)" и паролем "([^"]*)"$`, state.iRegisterUser)
	ctx.Step(`^регистрация должна пройти успешно$`, state.registrationShouldBeSuccess)
	ctx.Step(`^пользователь входит в систему с email "([^"]*)" и паролем "([^"]*)"$`, state.iLoginUser)
	ctx.Step(`^система возвращает пару токенов$`, state.iShouldGetTokenPair)
	ctx.Step(`^пользователь обращается к "защищенному ресурсу" с полученным токеном$`, state.iAccessProtectedResource)
	ctx.Step(`^доступ должен быть разрешен$`, state.accessShouldBeAllowed)
	ctx.Step(`^идентификатор пользователя в заголовке ответа не должен быть пустым$`, state.userIdShouldNotBeEmpty)
	ctx.Step(`^пользователь обновляет токены используя Refresh токен$`, state.iRefreshTokens)
	ctx.Step(`^система возвращает новую пару токенов$`, state.iShouldGetTokenPair)
	ctx.Step(`^новые токены должны отличаться от старых$`, state.newTokensShouldBeDifferent)
	ctx.Step(`^старый Access токен должен стать невалидным через (\d+) секунд$`, state.oldAccessTokenShouldBeInvalid)
}
