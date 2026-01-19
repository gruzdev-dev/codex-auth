//go:build integration

package bdd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	"github.com/cucumber/godog"
	"github.com/gorilla/mux"

	"github.com/gruzdev-dev/codex-auth/adapters/hasher"
	authHttp "github.com/gruzdev-dev/codex-auth/adapters/http"
	"github.com/gruzdev-dev/codex-auth/adapters/storage/postgres"
	"github.com/gruzdev-dev/codex-auth/adapters/token"
	"github.com/gruzdev-dev/codex-auth/core/service"
)

type validationTestState struct {
	router       *mux.Router
	lastResponse *httptest.ResponseRecorder
	reqBody      authHttp.RegisterRequest
}

func newValidationTestState() *validationTestState {
	repo := postgres.NewUserRepo(dbPool)
	hash := hasher.NewBcryptHasher()
	tm := token.NewJWTManager("val-secret", 15*time.Minute)
	validator := service.NewValidationService()
	profileProvider := &noopProfileProvider{}

	svc := service.NewUserService(repo, hash, tm, validator, profileProvider)
	handler := authHttp.NewHandler(svc)

	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	return &validationTestState{
		router: router,
	}
}

func (t *validationTestState) dbIsClean(ctx context.Context) error {
	_, err := dbPool.Exec(ctx, "TRUNCATE TABLE users")
	return err
}

func (t *validationTestState) iPrepareRegistration(ctx context.Context) error {
	t.reqBody = authHttp.RegisterRequest{}
	t.lastResponse = nil
	return nil
}

func (t *validationTestState) iSetEmail(ctx context.Context, email string) error {
	t.reqBody.Email = email
	return nil
}

func (t *validationTestState) iSetPassword(ctx context.Context, password string) error {
	t.reqBody.Password = password
	return nil
}

func (t *validationTestState) iSetPasswordLength(ctx context.Context, length int) error {
	if length < 0 {
		return fmt.Errorf("length cannot be negative")
	}
	t.reqBody.Password = strings.Repeat("a", length)
	return nil
}

func (t *validationTestState) iSendRequest(ctx context.Context) error {
	bodyBytes, _ := json.Marshal(t.reqBody)
	t.lastResponse = httptest.NewRecorder()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/register", bytes.NewBuffer(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(ctx)

	t.router.ServeHTTP(t.lastResponse, req)
	return nil
}

func (t *validationTestState) iShouldGetStatus(ctx context.Context, status int) error {
	if t.lastResponse.Code != status {
		return fmt.Errorf("expected status %d, got %d. Body: %s", status, t.lastResponse.Code, t.lastResponse.Body.String())
	}
	return nil
}

func (t *validationTestState) iShouldGetBodyString(ctx context.Context, expectedStr string) error {
	body := t.lastResponse.Body.String()
	if !strings.Contains(body, expectedStr) {
		return fmt.Errorf("response body does not contain '%s'. Got: %s", expectedStr, body)
	}
	return nil
}

func InitializeValidationScenario(ctx *godog.ScenarioContext) {
	state := newValidationTestState()

	ctx.Step(`^база данных очищена$`, state.dbIsClean)
	ctx.Step(`^я подготавливаю запрос на регистрацию$`, state.iPrepareRegistration)
	ctx.Step(`^я указываю email "([^"]*)"$`, state.iSetEmail)
	ctx.Step(`^я указываю пароль "([^"]*)"$`, state.iSetPassword)
	ctx.Step(`^я указываю пароль длиной (\d+) символов$`, state.iSetPasswordLength)
	ctx.Step(`^я отправляю запрос регистрации$`, state.iSendRequest)
	ctx.Step(`^я должен получить HTTP статус (\d+)$`, state.iShouldGetStatus)
	ctx.Step(`^тело ответа должно содержать текст "([^"]*)"$`, state.iShouldGetBodyString)
}
