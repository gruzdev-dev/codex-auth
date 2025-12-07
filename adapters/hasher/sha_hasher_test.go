package hasher

import (
	"testing"
)

func TestSHA256Hasher_Hash(t *testing.T) {
	hasher := NewSHA256Hasher()
	password := "testpassword123"

	hash, err := hasher.Hash(password)
	if err != nil {
		t.Fatalf("Hash() error = %v", err)
	}

	if hash == "" {
		t.Error("Hash() returned empty string")
	}
}

func TestSHA256Hasher_Compare_Success(t *testing.T) {
	hasher := NewSHA256Hasher()
	password := "testpassword123"

	hash, err := hasher.Hash(password)
	if err != nil {
		t.Fatalf("Hash() error = %v", err)
	}

	err = hasher.Compare(hash, password)
	if err != nil {
		t.Errorf("Compare() error = %v, want nil", err)
	}
}

func TestSHA256Hasher_Compare_Failure(t *testing.T) {
	hasher := NewSHA256Hasher()
	password := "testpassword123"
	wrongPassword := "wrongpassword"

	hash, err := hasher.Hash(password)
	if err != nil {
		t.Fatalf("Hash() error = %v", err)
	}

	err = hasher.Compare(hash, wrongPassword)
	if err == nil {
		t.Error("Compare() error = nil, want error")
	}
}

func TestSHA256Hasher_Compare_InvalidFormat(t *testing.T) {
	hasher := NewSHA256Hasher()
	invalidHash := "invalidhashformat"

	err := hasher.Compare(invalidHash, "password")
	if err == nil {
		t.Error("Compare() error = nil, want error")
	}
}
