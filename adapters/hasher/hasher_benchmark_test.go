package hasher

import (
	"testing"
)

var testPassword = "testpassword123456789"

func BenchmarkBcrypt_Hash(b *testing.B) {
	hasher := NewBcryptHasher()

	for b.Loop() {
		_, err := hasher.Hash(testPassword)
		if err != nil {
			b.Fatalf("Hash() error = %v", err)
		}
	}
}

func BenchmarkSHA256_Hash(b *testing.B) {
	hasher := NewSHA256Hasher()

	for b.Loop() {
		_, err := hasher.Hash(testPassword)
		if err != nil {
			b.Fatalf("Hash() error = %v", err)
		}
	}
}
