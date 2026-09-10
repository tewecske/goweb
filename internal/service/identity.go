package service

import (
	"errors"
	"net/mail"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	maxEmailLength    = 255
	maxUsernameLength = 32
)

var (
	// ErrInvalidEmail identifies an email value that cannot be used as an account identity.
	ErrInvalidEmail = errors.New("service: invalid email")
	// ErrInvalidUsername identifies a username value that cannot be used as an account identity.
	ErrInvalidUsername = errors.New("service: invalid username")
)

// NormalizeEmail trims and lowercases an optional email identity, then checks
// that its normalized form is a single usable email address.
func NormalizeEmail(raw string) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(raw))
	if normalized == "" {
		return "", nil
	}
	if utf8.RuneCountInString(normalized) > maxEmailLength {
		return "", ErrInvalidEmail
	}

	address, err := mail.ParseAddress(normalized)
	if err != nil || address.Address != normalized {
		return "", ErrInvalidEmail
	}
	return normalized, nil
}

// NormalizeUsername trims and lowercases an optional username identity. Usernames
// cannot contain whitespace or '@', which keeps them distinct from email input.
func NormalizeUsername(raw string) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(raw))
	if normalized == "" {
		return "", nil
	}
	if utf8.RuneCountInString(normalized) > maxUsernameLength {
		return "", ErrInvalidUsername
	}
	for _, character := range normalized {
		if character == '@' || unicode.IsSpace(character) {
			return "", ErrInvalidUsername
		}
	}
	return normalized, nil
}
