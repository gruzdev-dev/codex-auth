package hasher

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/gruzdev-dev/codex-auth/core/ports"
)

type SHA256Hasher struct{}

func NewSHA256Hasher() ports.PasswordHasher {
	return &SHA256Hasher{}
}

func (h *SHA256Hasher) Hash(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	hash := sha256.Sum256(append([]byte(password), salt...))
	return fmt.Sprintf("%s:%s", hex.EncodeToString(salt), hex.EncodeToString(hash[:])), nil
}

func (h *SHA256Hasher) Compare(hashedPassword, password string) error {
	parts := strings.Split(hashedPassword, ":")
	if len(parts) != 2 {
		return errors.New("invalid hash format")
	}

	salt, err := hex.DecodeString(parts[0])
	if err != nil {
		return err
	}

	expectedHash, err := hex.DecodeString(parts[1])
	if err != nil {
		return err
	}

	hash := sha256.Sum256(append([]byte(password), salt...))
	if hex.EncodeToString(hash[:]) != hex.EncodeToString(expectedHash) {
		return errors.New("password mismatch")
	}

	return nil
}
