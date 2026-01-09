package postgres

import (
	"context"
	"encoding/json"
	"errors"

	"codex-auth/core/domain"
	coreerrors "codex-auth/core/errors"
	"codex-auth/core/ports"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type UserRepo struct {
	pool *pgxpool.Pool
}

func NewUserRepo(pool *pgxpool.Pool) ports.UserRepository {
	return &UserRepo{
		pool: pool,
	}
}

func (r *UserRepo) Save(ctx context.Context, user *domain.User) error {
	metadataJSON, err := json.Marshal(user.Metadata)
	if err != nil {
		return err
	}

	query := `INSERT INTO users (id, email, password_hash, role, metadata, created_at) VALUES ($1, $2, $3, $4, $5, $6)`
	_, err = r.pool.Exec(ctx, query, user.ID, user.Email, user.PasswordHash, user.Role, metadataJSON, user.CreatedAt)

	if err != nil {
		var pgErr *pgconn.PgError
		// Unique Violation in Postgres
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return coreerrors.ErrUserAlreadyExists
		}
		return err
	}
	return nil
}

func (r *UserRepo) GetByEmail(ctx context.Context, email string) (*domain.User, error) {
	query := `SELECT id, email, password_hash, role, metadata, created_at FROM users WHERE email = $1`
	var user domain.User
	var metadataJSON []byte
	err := r.pool.QueryRow(ctx, query, email).Scan(
		&user.ID,
		&user.Email,
		&user.PasswordHash,
		&user.Role,
		&metadataJSON,
		&user.CreatedAt,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, coreerrors.ErrUserNotFound
		}
		return nil, err
	}

	if metadataJSON == nil {
		user.Metadata = make(map[string]string)
	} else {
		if err := json.Unmarshal(metadataJSON, &user.Metadata); err != nil {
			return nil, err
		}
	}

	return &user, nil
}

func (r *UserRepo) GetByID(ctx context.Context, id string) (*domain.User, error) {
	query := `SELECT id, email, password_hash, role, metadata, created_at FROM users WHERE id = $1`
	var user domain.User
	var metadataJSON []byte
	err := r.pool.QueryRow(ctx, query, id).Scan(
		&user.ID,
		&user.Email,
		&user.PasswordHash,
		&user.Role,
		&metadataJSON,
		&user.CreatedAt,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, coreerrors.ErrUserNotFound
		}
		return nil, err
	}

	if metadataJSON == nil {
		user.Metadata = make(map[string]string)
	} else {
		if err := json.Unmarshal(metadataJSON, &user.Metadata); err != nil {
			return nil, err
		}
	}

	return &user, nil
}
