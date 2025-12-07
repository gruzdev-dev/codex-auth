package hasher

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSHA256Hasher_Hash(t *testing.T) {
	hasher := NewSHA256Hasher()
	password := "testpassword123"

	hash, err := hasher.Hash(password)
	require.NoError(t, err)
	assert.NotEmpty(t, hash)
}

func TestSHA256Hasher_Compare_StatementCoverage(t *testing.T) {
	hasher := NewSHA256Hasher()

	validPassword := "testpassword123"
	validHash, err := hasher.Hash(validPassword)
	require.NoError(t, err)

	tests := []struct {
		name        string
		statementID string
		hashedPass  string
		password    string
		expectError bool
		validate    func(t *testing.T, err error)
	}{
		{
			// Covers: main success path, all decode operations succeed, hash comparison returns true, return nil
			name:        "Case 1: Success - Valid hash and correct password",
			statementID: "S1",
			hashedPass:  validHash,
			password:    validPassword,
			expectError: false,
			validate: func(t *testing.T, err error) {
				assert.NoError(t, err)
			},
		},
		{
			// Covers: if len(parts) != 2 branch, return "invalid hash format"
			name:        "Case 2: Format Error - String without colon",
			statementID: "S2",
			hashedPass:  "invalid",
			password:    "password",
			expectError: true,
			validate: func(t *testing.T, err error) {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "invalid hash format")
			},
		},
		{
			// Covers: hex.DecodeString(parts[0]) error branch, return err after salt decode
			name:        "Case 3: Salt Decode Error - Invalid hex in salt part",
			statementID: "S3",
			hashedPass:  "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
			password:    "password",
			expectError: true,
			validate: func(t *testing.T, err error) {
				assert.Error(t, err)
			},
		},
		{
			// Covers: hex.DecodeString(parts[1]) error branch, return err after hash decode
			name:        "Case 4: Hash Decode Error - Invalid hex in hash part",
			statementID: "S4",
			hashedPass:  "deadbeefdeadbeefdeadbeefdeadbeef:ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ",
			password:    "password",
			expectError: true,
			validate: func(t *testing.T, err error) {
				assert.Error(t, err)
			},
		},
		{
			// Covers: hash comparison mismatch branch, return "password mismatch"
			name:        "Case 5: Mismatch - Valid hash but wrong password",
			statementID: "S5",
			hashedPass:  validHash,
			password:    "wrongpassword",
			expectError: true,
			validate: func(t *testing.T, err error) {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "password mismatch")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := hasher.Compare(tt.hashedPass, tt.password)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			if tt.validate != nil {
				tt.validate(t, err)
			}
		})
	}
}
