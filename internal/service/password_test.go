package service

import (
	"errors"
	"strings"
	"testing"
)

func TestValidatePassword(t *testing.T) {
	tests := []struct {
		name      string
		password  string
		expected  error
		wantValid bool
	}{
		{name: "minimum length", password: strings.Repeat("p", MinimumPasswordLength), wantValid: true},
		{name: "maximum length", password: strings.Repeat("p", MaximumPasswordLength), wantValid: true},
		{name: "unicode characters count as one each", password: "pässwörd", wantValid: true},
		{name: "short password", password: strings.Repeat("p", MinimumPasswordLength-1), expected: ErrPasswordTooShort},
		{name: "long password", password: strings.Repeat("p", MaximumPasswordLength+1), expected: ErrPasswordTooLong},
		{name: "invalid utf eight", password: string([]byte{'p', 0xff, 'p', 'p', 'p', 'p', 'p', 'p'}), expected: ErrInvalidPassword},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := ValidatePassword(test.password)
			if test.wantValid {
				if err != nil {
					t.Fatalf("ValidatePassword() error = %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, test.expected) {
				t.Fatalf("ValidatePassword() error = %v, want errors.Is(_, %v)", err, test.expected)
			}
			if strings.Contains(err.Error(), test.password) {
				t.Error("ValidatePassword() error exposes password")
			}
		})
	}
}
