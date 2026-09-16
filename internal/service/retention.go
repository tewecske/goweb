package service

import (
	"context"
	"errors"
	"fmt"
	"time"
)

const (
	// DefaultLoginAttemptRetention keeps durable sign-in history for support.
	DefaultLoginAttemptRetention = 30 * 24 * time.Hour
	// DefaultUsageRetention bounds anonymous usage-event growth.
	DefaultUsageRetention = 90 * 24 * time.Hour
)

var (
	// ErrNilRetentionRepository identifies missing retention persistence.
	ErrNilRetentionRepository = errors.New("service: nil retention repository")
	// ErrInvalidRetentionConfig identifies unusable retention periods.
	ErrInvalidRetentionConfig = errors.New("service: invalid retention config")
)

// RetentionRepository removes records that are expired, consumed, or older
// than a cutoff. Every operation is idempotent and returns the removed count.
type RetentionRepository interface {
	DeleteExpiredEmailConfirmationTokens(context.Context, int64) (int, error)
	DeleteExpiredPasswordResetTokens(context.Context, int64) (int, error)
	DeleteExpiredOAuthStates(context.Context, int64) (int, error)
	DeleteLoginAttemptsBefore(context.Context, int64) (int, error)
	DeleteUsageEventsBefore(context.Context, int64) (int, error)
}

// RetentionService removes expired credentials and old operational history
// according to configured retention. It never reads or returns secret values.
type RetentionService struct {
	repository     RetentionRepository
	loginRetention time.Duration
	usageRetention time.Duration
	now            func() time.Time
}

// NewRetentionService constructs retention cleanup with explicit periods.
func NewRetentionService(repository RetentionRepository, loginRetention, usageRetention time.Duration) (*RetentionService, error) {
	if repository == nil {
		return nil, ErrNilRetentionRepository
	}
	if loginRetention <= 0 || usageRetention <= 0 {
		return nil, ErrInvalidRetentionConfig
	}
	return &RetentionService{
		repository:     repository,
		loginRetention: loginRetention,
		usageRetention: usageRetention,
		now:            time.Now,
	}, nil
}

// CleanupTokens removes consumed or expired confirmation tokens, password-reset
// tokens, and OAuth flow states and returns the total removed.
func (s *RetentionService) CleanupTokens(ctx context.Context) (int, error) {
	if err := s.validate(ctx); err != nil {
		return 0, err
	}
	now := s.now().Unix()
	removed := 0
	for _, remove := range []func(context.Context, int64) (int, error){
		s.repository.DeleteExpiredEmailConfirmationTokens,
		s.repository.DeleteExpiredPasswordResetTokens,
		s.repository.DeleteExpiredOAuthStates,
	} {
		count, err := remove(ctx, now)
		if err != nil {
			return removed, fmt.Errorf("clean up tokens: %w", err)
		}
		removed += count
	}
	return removed, nil
}

// CleanupLoginAttempts removes sign-in history older than the login retention.
func (s *RetentionService) CleanupLoginAttempts(ctx context.Context) (int, error) {
	if err := s.validate(ctx); err != nil {
		return 0, err
	}
	cutoff := s.now().Add(-s.loginRetention).Unix()
	count, err := s.repository.DeleteLoginAttemptsBefore(ctx, cutoff)
	if err != nil {
		return 0, fmt.Errorf("clean up login attempts: %w", err)
	}
	return count, nil
}

// CleanupUsageEvents removes usage events older than the usage retention.
func (s *RetentionService) CleanupUsageEvents(ctx context.Context) (int, error) {
	if err := s.validate(ctx); err != nil {
		return 0, err
	}
	cutoff := s.now().Add(-s.usageRetention).Unix()
	count, err := s.repository.DeleteUsageEventsBefore(ctx, cutoff)
	if err != nil {
		return 0, fmt.Errorf("clean up usage events: %w", err)
	}
	return count, nil
}

// LoginRetention reports the configured sign-in history period.
func (s *RetentionService) LoginRetention() time.Duration {
	if s == nil {
		return 0
	}
	return s.loginRetention
}

// UsageRetention reports the configured usage-event period.
func (s *RetentionService) UsageRetention() time.Duration {
	if s == nil {
		return 0
	}
	return s.usageRetention
}

func (s *RetentionService) validate(ctx context.Context) error {
	if s == nil || s.repository == nil || s.now == nil || s.loginRetention <= 0 || s.usageRetention <= 0 {
		return ErrInvalidRetentionConfig
	}
	if ctx == nil {
		return errors.New("service: nil retention context")
	}
	return nil
}
