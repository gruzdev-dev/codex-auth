package hasher

import (
	"encoding/json"
	"os"
	"testing"
)

func loadBenchmarkData(b *testing.B) []string {
	if os.Getenv("RUN_BENCHMARKS") == "" {
		b.Skip("Skipping benchmark: set RUN_BENCHMARKS=1")
	}

	data, err := os.ReadFile("benchmark_passwords.json")
	if err != nil {
		b.Skip("Skipping: data file not found")
	}

	var passwords []string
	if err := json.Unmarshal(data, &passwords); err != nil {
		b.Fatalf("Failed to parse JSON: %v", err)
	}

	return passwords
}

func BenchmarkBcrypt_Hash(b *testing.B) {
	passwords := loadBenchmarkData(b)
	hasher := NewBcryptHasher()

	b.ResetTimer()

	for i := 0; b.Loop(); i++ {
		p := passwords[i%len(passwords)]
		_, err := hasher.Hash(p)
		if err != nil {
			b.Fatalf("Hash() error = %v", err)
		}
	}
}

func BenchmarkSHA256_Hash(b *testing.B) {
	passwords := loadBenchmarkData(b)
	hasher := NewSHA256Hasher()

	b.ResetTimer()

	for i := 0; b.Loop(); i++ {
		p := passwords[i%len(passwords)]
		_, err := hasher.Hash(p)
		if err != nil {
			b.Fatalf("Hash() error = %v", err)
		}
	}
}
