package service

import (
	"errors"
	"strings"
	"testing"
)

var testPasswordHashConfig = PasswordHashConfig{
	Memory:     8 * 1024,
	Time:       1,
	Threads:    1,
	SaltLength: 16,
	KeyLength:  32,
}

func TestPasswordHasherHashAndVerify(t *testing.T) {
	hasher, err := NewPasswordHasher(testPasswordHashConfig)
	if err != nil {
		t.Fatalf("NewPasswordHasher() error = %v, want nil", err)
	}

	first, err := hasher.Hash("correct horse battery staple")
	if err != nil {
		t.Fatalf("Hash() error = %v, want nil", err)
	}
	second, err := hasher.Hash("correct horse battery staple")
	if err != nil {
		t.Fatalf("Hash() second error = %v, want nil", err)
	}
	if first == second {
		t.Fatal("Hash() returned identical hashes for separate salts")
	}
	if !strings.HasPrefix(first, "$argon2id$v=19$") {
		t.Fatalf("Hash() = %q, want Argon2id version 19 encoding", first)
	}

	valid, err := hasher.Verify("correct horse battery staple", first)
	if err != nil {
		t.Fatalf("Verify() error = %v, want nil", err)
	}
	if !valid {
		t.Fatal("Verify() = false for matching password")
	}
	valid, err = hasher.Verify("wrong horse battery staple", first)
	if err != nil {
		t.Fatalf("Verify() wrong password error = %v, want nil", err)
	}
	if valid {
		t.Fatal("Verify() = true for non-matching password")
	}
}

func TestPasswordHasherRejectsInvalidHashesAndPasswords(t *testing.T) {
	hasher, err := NewPasswordHasher(testPasswordHashConfig)
	if err != nil {
		t.Fatalf("NewPasswordHasher() error = %v, want nil", err)
	}

	if _, err := hasher.Hash("short"); !errors.Is(err, ErrPasswordTooShort) {
		t.Fatalf("Hash(short) error = %v, want errors.Is(_, %v)", err, ErrPasswordTooShort)
	}
	for _, encoded := range []string{"", "not-a-hash", "$argon2id$v=18$m=8192,t=1,p=1$AA$AA"} {
		encoded := encoded
		t.Run("invalid hash "+encoded, func(t *testing.T) {
			valid, err := hasher.Verify("correct horse battery staple", encoded)
			if !errors.Is(err, ErrInvalidPasswordHash) {
				t.Fatalf("Verify() error = %v, want errors.Is(_, %v)", err, ErrInvalidPasswordHash)
			}
			if valid {
				t.Fatal("Verify() = true for invalid stored hash")
			}
			if encoded != "" && strings.Contains(err.Error(), encoded) {
				t.Error("Verify() error exposes stored hash")
			}
		})
	}
}

func TestNewPasswordHasherRejectsInvalidConfig(t *testing.T) {
	tests := []struct {
		name   string
		config PasswordHashConfig
	}{
		{name: "zero memory", config: PasswordHashConfig{Time: 1, Threads: 1, SaltLength: 16, KeyLength: 32}},
		{name: "zero time", config: PasswordHashConfig{Memory: 8192, Threads: 1, SaltLength: 16, KeyLength: 32}},
		{name: "zero threads", config: PasswordHashConfig{Memory: 8192, Time: 1, SaltLength: 16, KeyLength: 32}},
		{name: "short salt", config: PasswordHashConfig{Memory: 8192, Time: 1, Threads: 1, SaltLength: 7, KeyLength: 32}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewPasswordHasher(test.config); !errors.Is(err, ErrInvalidPasswordHashConfig) {
				t.Fatalf("NewPasswordHasher() error = %v, want errors.Is(_, %v)", err, ErrInvalidPasswordHashConfig)
			}
		})
	}
}
