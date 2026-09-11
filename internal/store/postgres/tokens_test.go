package postgres

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/tewecske/goweb/internal/service"
)

func TestTokenRepositoryConstructors(t *testing.T) {
	constructors := []struct {
		name string
		new  func(*sql.DB) (any, error)
	}{
		{name: "confirmation", new: func(db *sql.DB) (any, error) { return NewEmailConfirmationTokenRepository(db) }},
		{name: "password reset", new: func(db *sql.DB) (any, error) { return NewPasswordResetTokenRepository(db) }},
	}
	for _, constructor := range constructors {
		t.Run(constructor.name, func(t *testing.T) {
			if _, err := constructor.new(nil); !errors.Is(err, ErrNilDatabase) {
				t.Fatalf("constructor(nil) error = %v, want %v", err, ErrNilDatabase)
			}
			if repository, err := constructor.new(&sql.DB{}); err != nil || repository == nil {
				t.Fatalf("constructor() = %v, %v", repository, err)
			}
		})
	}
}

func TestTokenRepositoriesRejectNilContext(t *testing.T) {
	confirmation, err := NewEmailConfirmationTokenRepository(&sql.DB{})
	if err != nil {
		t.Fatal(err)
	}
	if err := confirmation.CreateEmailConfirmationToken(nil, service.EmailConfirmationToken{}); !errors.Is(err, ErrNilContext) {
		t.Fatalf("confirmation Create(nil) = %v, want %v", err, ErrNilContext)
	}
	reset, err := NewPasswordResetTokenRepository(&sql.DB{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reset.ConsumePasswordResetToken(nil, "token", 1); !errors.Is(err, ErrNilContext) {
		t.Fatalf("reset Consume(nil) = %v, want %v", err, ErrNilContext)
	}
}

func TestMapTokenErrorUsesTokenSpecificNotFound(t *testing.T) {
	if err := mapTokenError(sql.ErrNoRows, service.ErrEmailConfirmationTokenNotFound); !errors.Is(err, service.ErrEmailConfirmationTokenNotFound) {
		t.Fatalf("confirmation mapping = %v", err)
	}
	if err := mapTokenError(sql.ErrNoRows, service.ErrPasswordResetTokenNotFound); !errors.Is(err, service.ErrPasswordResetTokenNotFound) {
		t.Fatalf("reset mapping = %v", err)
	}
	if err := mapTokenError(context.Canceled, service.ErrPasswordResetTokenNotFound); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation mapping = %v", err)
	}
}
