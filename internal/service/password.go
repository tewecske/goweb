package service

import (
	"errors"
	"unicode/utf8"
)

const (
	// MinimumPasswordLength is the smallest accepted password length in characters.
	MinimumPasswordLength = 8
	// MaximumPasswordLength is the largest accepted password length in characters.
	MaximumPasswordLength = 128
)

var (
	// ErrInvalidPassword identifies a password that is not valid UTF-8.
	ErrInvalidPassword = errors.New("service: invalid password")
	// ErrPasswordTooShort identifies a password below the minimum length.
	ErrPasswordTooShort = errors.New("service: password too short")
	// ErrPasswordTooLong identifies a password above the maximum length.
	ErrPasswordTooLong = errors.New("service: password too long")
)

// ValidatePassword checks password length without changing or exposing its
// value. Passwords are measured in Unicode characters, not bytes.
func ValidatePassword(password string) error {
	if !utf8.ValidString(password) {
		return ErrInvalidPassword
	}

	length := utf8.RuneCountInString(password)
	if length < MinimumPasswordLength {
		return ErrPasswordTooShort
	}
	if length > MaximumPasswordLength {
		return ErrPasswordTooLong
	}
	return nil
}
