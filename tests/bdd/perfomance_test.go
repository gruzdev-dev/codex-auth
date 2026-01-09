//go:build integration

package bdd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"runtime"
	"time"

	"github.com/cucumber/godog"
	"github.com/gorilla/mux"

	"codex-auth/adapters/hasher"
	authHttp "codex-auth/adapters/http"
	"codex-auth/adapters/storage/postgres"
	"codex-auth/adapters/token"
	"codex-auth/core/ports"
	"codex-auth/core/service"
)

type performanceTestState struct {
	router          *mux.Router
	usersToCreate   []authHttp.RegisterRequest
	durations       map[string]time.Duration
	lastRunDuration time.Duration
	memUsage        uint64
}

func newPerformanceTestState() *performanceTestState {
	return &performanceTestState{
		durations: make(map[string]time.Duration),
	}
}

func (t *performanceTestState) iPrepareDataset(count int) error {
	t.usersToCreate = make([]authHttp.RegisterRequest, count)
	for i := 0; i < count; i++ {
		t.usersToCreate[i] = authHttp.RegisterRequest{
			Email:    fmt.Sprintf("loadtest_%d_%d@example.com", time.Now().UnixNano(), i),
			Password: "pass_long_enough_" + fmt.Sprintf("%d", i),
		}
	}
	return nil
}

func (t *performanceTestState) iSwitchAlgorithm(algo string) error {
	repo := postgres.NewUserRepo(dbPool)
	tm := token.NewJWTManager("perf-secret", 15*time.Minute)

	var h ports.PasswordHasher
	if algo == "SHA256" {
		h = hasher.NewSHA256Hasher()
	} else {
		h = hasher.NewBcryptHasher()
	}

	validator := service.NewValidationService()
	profileProvider := &noopProfileProvider{}
	svc := service.NewUserService(repo, h, tm, validator, profileProvider)
	handler := authHttp.NewHandler(svc)

	t.router = mux.NewRouter()
	handler.RegisterRoutes(t.router)

	return nil
}

func (t *performanceTestState) iSendBulkRequests(ctx context.Context) error {
	runtime.GC()
	var m1, m2 runtime.MemStats
	runtime.ReadMemStats(&m1)

	start := time.Now()

	for _, u := range t.usersToCreate {
		body, _ := json.Marshal(u)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/register", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()
		t.router.ServeHTTP(rr, req)

		if rr.Code != http.StatusCreated {
			return fmt.Errorf("fail on %s: %d body: %s", u.Email, rr.Code, rr.Body.String())
		}
	}

	t.lastRunDuration = time.Since(start)

	runtime.ReadMemStats(&m2)
	t.memUsage = m2.Alloc / 1024 / 1024

	return nil
}

func (t *performanceTestState) allUsersShouldBeCreated(ctx context.Context) error {
	var count int
	err := dbPool.QueryRow(ctx, "SELECT COUNT(*) FROM users").Scan(&count)
	if err != nil {
		return err
	}

	if count != len(t.usersToCreate) {
		return fmt.Errorf("expected %d users in DB, found %d", len(t.usersToCreate), count)
	}
	return nil
}

func (t *performanceTestState) iRecordTimeAs(label string) error {
	t.durations[label] = t.lastRunDuration
	fmt.Printf("[%s] Time: %v, Mem: %d MB\n", label, t.lastRunDuration, t.memUsage)
	return nil
}

func (t *performanceTestState) compareTimes(fastMetric, slowMetric string, factor int) error {
	fast := t.durations[fastMetric]
	slow := t.durations[slowMetric]

	if fast == 0 {
		return fmt.Errorf("metric %s is 0", fastMetric)
	}

	ratio := float64(slow) / float64(fast)
	if ratio < float64(factor) {
		return fmt.Errorf("expected %s to be %dx slower than %s, but ratio is %.2f (Fast: %v, Slow: %v)", slowMetric, factor, fastMetric, ratio, fast, slow)
	}
	return nil
}

func (t *performanceTestState) executionTimeShouldNotExceed(minutes int) error {
	limit := time.Duration(minutes) * time.Minute

	if t.lastRunDuration > limit {
		return fmt.Errorf("execution took %v, limit is %v", t.lastRunDuration, limit)
	}

	fmt.Printf("[TIME] Execution: %v, limit: %v\n", t.lastRunDuration, limit)

	return nil
}

func (t *performanceTestState) memoryShouldNotExceed(limitMB int) error {
	if t.memUsage > uint64(limitMB) {
		return fmt.Errorf("memory usage %d MB exceeded limit %d MB", t.memUsage, limitMB)
	}

	fmt.Printf("[MEMORY] Usage: %d MB, limit: %d MB\n", t.memUsage, limitMB)

	return nil
}

func InitializePerformanceScenario(ctx *godog.ScenarioContext) {
	state := newPerformanceTestState()

	ctx.Step(`^база данных очищена$`, func() error {
		_, err := dbPool.Exec(context.Background(), "TRUNCATE TABLE users")
		return err
	})

	ctx.Step(`^я подготавливаю набор данных из (\d+) пользователей$`, state.iPrepareDataset)
	ctx.Step(`^я генерирую датасет размером (\d+) записей$`, state.iPrepareDataset)
	ctx.Step(`^я переключаю систему на алгоритм "([^"]*)"$`, state.iSwitchAlgorithm)
	ctx.Step(`^я отправляю запросы на регистрацию всех пользователей через API$`, state.iSendBulkRequests)
	ctx.Step(`^я выполняю массовую регистрацию через API$`, state.iSendBulkRequests)
	ctx.Step(`^все пользователи должны быть успешно созданы в БД$`, state.allUsersShouldBeCreated)
	ctx.Step(`^я фиксирую время выполнения как "([^"]*)"$`, state.iRecordTimeAs)
	ctx.Step(`^"([^"]*)" должно быть меньше "([^"]*)" минимум в (\d+) раз$`, state.compareTimes)
	ctx.Step(`^время обработки не должно превышать (\d+) минут$`, state.executionTimeShouldNotExceed)
	ctx.Step(`^потребление памяти не должно превышать (\d+) Мб$`, state.memoryShouldNotExceed)
}
