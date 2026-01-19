//go:build integration

package bdd

import (
	"context"
	"io"
	"log"
	"testing"
	"time"

	"github.com/gruzdev-dev/codex-auth/migrations"

	"github.com/cucumber/godog"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

var (
	dbPool           *pgxpool.Pool
	connectionString string
)

func TestMain(m *testing.M) {
	ctx := context.Background()

	quietLogger := log.New(io.Discard, "", 0)

	pgContainer, err := postgres.Run(ctx,
		"postgres:16-alpine",
		postgres.WithDatabase("codex_test"),
		postgres.WithUsername("testuser"),
		postgres.WithPassword("testpass"),
		postgres.WithSQLDriver("pgx"),
		testcontainers.WithLogger(quietLogger),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(5*time.Second)),
	)
	if err != nil {
		log.Fatalf("failed to start container: %s", err)
	}

	connectionString, err = pgContainer.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		log.Fatalf("failed to get connection string: %s", err)
	}

	dbPool, err = pgxpool.New(ctx, connectionString)
	if err != nil {
		log.Fatalf("failed to create db pool: %s", err)
	}

	if err := dbPool.Ping(ctx); err != nil {
		log.Fatalf("failed to ping db: %s", err)
	}

	initSchema(ctx)

	opts := godog.Options{
		Format:      "pretty",
		Paths:       []string{"features"},
		Randomize:   time.Now().UTC().UnixNano(),
		Concurrency: 1,
		NoColors:    true,
	}

	status := godog.TestSuite{
		Name:                 "godogs",
		TestSuiteInitializer: InitializeTestSuite,
		ScenarioInitializer:  InitializeScenario,
		Options:              &opts,
	}.Run()

	dbPool.Close()

	if err := pgContainer.Terminate(ctx); err != nil {
		log.Fatalf("failed to terminate container: %s", err)
	}

	if status != 0 {
		log.Fatal("non-zero exit code")
	}
}

func initSchema(ctx context.Context) {
	migrationFiles := []string{
		"001_create_users_table.up.sql",
		"002_add_metadata_column.up.sql",
	}

	for _, migrationFile := range migrationFiles {
		migrationSQL, err := migrations.FS.ReadFile(migrationFile)
		if err != nil {
			log.Fatalf("failed to read migration file %s: %s", migrationFile, err)
		}

		_, err = dbPool.Exec(ctx, string(migrationSQL))
		if err != nil {
			log.Fatalf("failed to apply migration %s: %s", migrationFile, err)
		}
	}
}

func InitializeTestSuite(ctx *godog.TestSuiteContext) {}

func InitializeScenario(ctx *godog.ScenarioContext) {
	InitializeAuthScenario(ctx)
	InitializeValidationScenario(ctx)
	InitializePerformanceScenario(ctx)
}
