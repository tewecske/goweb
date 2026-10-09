package service

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"runtime"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	maxPasswordHashMemory = 1 << 30
	maxPasswordHashTime   = 10
	maxPasswordHashBytes  = 1 << 20
)

var (
	// ErrInvalidPasswordHashConfig identifies unusable Argon2id parameters.
	ErrInvalidPasswordHashConfig = errors.New("service: invalid password hash config")
	// ErrInvalidPasswordHash identifies a malformed or unsupported stored hash.
	ErrInvalidPasswordHash = errors.New("service: invalid password hash")
)

// PasswordHashConfig controls Argon2id parameters for newly created hashes.
// Memory is measured in KiB; SaltLength and KeyLength are measured in bytes.
type PasswordHashConfig struct {
	Memory     uint32
	Time       uint32
	Threads    uint8
	SaltLength uint32
	KeyLength  uint32
}

// DefaultPasswordHashConfig is the baseline cost for new password hashes.
var DefaultPasswordHashConfig = PasswordHashConfig{
	Memory:     64 * 1024,
	Time:       3,
	Threads:    4,
	SaltLength: 16,
	KeyLength:  32,
}

// PasswordHasher creates and verifies Argon2id password hashes. Each
// derivation allocates Memory KiB, so concurrent derivations are capped to
// keep floods of sign-in, sign-up, or reset requests from exhausting memory;
// excess callers wait for a slot.
type PasswordHasher struct {
	config PasswordHashConfig
	slots  chan struct{}
}

// NewPasswordHasher constructs a hasher. A zero config selects the defaults;
// partially specified configs are rejected instead of silently weakened.
func NewPasswordHasher(config PasswordHashConfig) (*PasswordHasher, error) {
	config, err := normalizePasswordHashConfig(config)
	if err != nil {
		return nil, err
	}
	return &PasswordHasher{config: config, slots: make(chan struct{}, max(2, runtime.GOMAXPROCS(0)))}, nil
}

// derive runs one Argon2id derivation inside a concurrency slot.
func (h *PasswordHasher) derive(password string, salt []byte, config PasswordHashConfig) []byte {
	if h.slots != nil {
		h.slots <- struct{}{}
		defer func() { <-h.slots }()
	}
	return argon2.IDKey([]byte(password), salt, config.Time, config.Memory, config.Threads, config.KeyLength)
}

// Hash validates and hashes password with a fresh cryptographically random salt.
func (h *PasswordHasher) Hash(password string) (string, error) {
	if h == nil {
		return "", ErrInvalidPasswordHashConfig
	}
	config, err := normalizePasswordHashConfig(h.config)
	if err != nil {
		return "", err
	}
	if err := ValidatePassword(password); err != nil {
		return "", fmt.Errorf("validate password for hashing: %w", err)
	}

	salt := make([]byte, config.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate password salt: %w", err)
	}
	key := h.derive(password, salt, config)
	return encodePasswordHash(config, salt, key), nil
}

// Verify reports whether password matches encodedHash. Stored hash parameters
// control verification so changing defaults does not invalidate old passwords.
func (h *PasswordHasher) Verify(password, encodedHash string) (bool, error) {
	if h == nil {
		return false, ErrInvalidPasswordHashConfig
	}
	parsed, err := parsePasswordHash(encodedHash)
	if err != nil {
		return false, err
	}

	key := h.derive(password, parsed.salt, parsed.config)
	return subtle.ConstantTimeCompare(key, parsed.key) == 1, nil
}

func normalizePasswordHashConfig(config PasswordHashConfig) (PasswordHashConfig, error) {
	if config == (PasswordHashConfig{}) {
		config = DefaultPasswordHashConfig
	}
	if err := validatePasswordHashConfig(config); err != nil {
		return PasswordHashConfig{}, err
	}
	return config, nil
}

type parsedPasswordHash struct {
	config PasswordHashConfig
	salt   []byte
	key    []byte
}

func validatePasswordHashConfig(config PasswordHashConfig) error {
	if config.Memory == 0 || config.Memory > maxPasswordHashMemory || config.Time == 0 || config.Time > maxPasswordHashTime || config.Threads == 0 {
		return ErrInvalidPasswordHashConfig
	}
	minimumMemory := uint32(config.Threads) * 8
	if config.Memory < minimumMemory || config.SaltLength < 8 || config.SaltLength > maxPasswordHashBytes || config.KeyLength == 0 || config.KeyLength > maxPasswordHashBytes {
		return ErrInvalidPasswordHashConfig
	}
	return nil
}

func encodePasswordHash(config PasswordHashConfig, salt, key []byte) string {
	return fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		config.Memory,
		config.Time,
		config.Threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	)
}

func parsePasswordHash(encoded string) (parsedPasswordHash, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return parsedPasswordHash{}, ErrInvalidPasswordHash
	}

	version, err := parsePasswordHashParameter(parts[2], "v")
	if err != nil || version != argon2.Version {
		return parsedPasswordHash{}, ErrInvalidPasswordHash
	}
	parameters := strings.Split(parts[3], ",")
	if len(parameters) != 3 {
		return parsedPasswordHash{}, ErrInvalidPasswordHash
	}
	memory, err := parsePasswordHashParameter(parameters[0], "m")
	if err != nil {
		return parsedPasswordHash{}, ErrInvalidPasswordHash
	}
	timeCost, err := parsePasswordHashParameter(parameters[1], "t")
	if err != nil {
		return parsedPasswordHash{}, ErrInvalidPasswordHash
	}
	threads, err := parsePasswordHashParameter(parameters[2], "p")
	if err != nil || threads > 255 {
		return parsedPasswordHash{}, ErrInvalidPasswordHash
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return parsedPasswordHash{}, ErrInvalidPasswordHash
	}
	key, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return parsedPasswordHash{}, ErrInvalidPasswordHash
	}
	config := PasswordHashConfig{
		Memory:     uint32(memory),
		Time:       uint32(timeCost),
		Threads:    uint8(threads),
		SaltLength: uint32(len(salt)),
		KeyLength:  uint32(len(key)),
	}
	if err := validatePasswordHashConfig(config); err != nil {
		return parsedPasswordHash{}, ErrInvalidPasswordHash
	}
	return parsedPasswordHash{config: config, salt: salt, key: key}, nil
}

func parsePasswordHashParameter(raw, name string) (uint64, error) {
	prefix := name + "="
	if !strings.HasPrefix(raw, prefix) {
		return 0, ErrInvalidPasswordHash
	}
	value, err := strconv.ParseUint(strings.TrimPrefix(raw, prefix), 10, 32)
	if err != nil {
		return 0, ErrInvalidPasswordHash
	}
	return value, nil
}
