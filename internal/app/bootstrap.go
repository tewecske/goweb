// Package app owns explicit application dependency composition.
package app

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/tewecske/goweb/internal/config"
	"github.com/tewecske/goweb/internal/service"
)

// ErrBootstrapAdminForbidden identifies bootstrap seeding outside development.
var ErrBootstrapAdminForbidden = errors.New("app: bootstrap administrator is not allowed in production")

// EnsureBootstrapAdmin creates the configured development administrator when it
// is missing. It is idempotent and refuses to run in production. The bootstrap
// password is never returned, logged, or stored outside the password hash.
func EnsureBootstrapAdmin(ctx context.Context, graph *Graph, appConfig config.Config) error {
	if !appConfig.BootstrapAdminConfigured() {
		return nil
	}
	if appConfig.Environment == config.EnvironmentProduction {
		return ErrBootstrapAdminForbidden
	}
	if graph == nil || graph.Users == nil || graph.PasswordHasher == nil {
		return errors.New("app: invalid bootstrap administrator dependencies")
	}
	if ctx == nil {
		return errors.New("app: nil bootstrap administrator context")
	}
	email, err := service.NormalizeEmail(appConfig.BootstrapAdminEmail)
	if err != nil || email == "" {
		return config.ErrInvalidBootstrapAdmin
	}
	if _, err := graph.Users.FindUserByEmail(ctx, email); err == nil {
		return nil
	} else if !errors.Is(err, service.ErrUserNotFound) {
		return fmt.Errorf("find bootstrap administrator: %w", err)
	}
	hash, err := graph.PasswordHasher.Hash(appConfig.BootstrapAdminPassword.Reveal())
	if err != nil {
		return fmt.Errorf("hash bootstrap administrator password: %w", err)
	}
	now := time.Now().Unix()
	_, err = graph.Users.CreateUser(ctx, service.User{
		Email:           &email,
		PasswordHash:    &hash,
		IsAdmin:         true,
		Theme:           "light",
		Locale:          "en",
		CreatedAt:       now,
		EmailVerifiedAt: &now,
	})
	if errors.Is(err, service.ErrDuplicateEmail) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("create bootstrap administrator: %w", err)
	}
	return nil
}
