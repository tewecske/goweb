package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

const (
	maxRateLimitKeyLength  = 255
	signInIdentifierAction = "signin.identifier"
	signInOriginAction     = "signin.origin"
)

var (
	// ErrInvalidRateLimitConfig identifies unusable limiter settings.
	ErrInvalidRateLimitConfig = errors.New("service: invalid rate limit config")
	// ErrInvalidRateLimitKey identifies an empty or oversized limiter dimension.
	ErrInvalidRateLimitKey = errors.New("service: invalid rate limit key")
	// ErrRateLimitCapacity identifies a limiter at its configured key bound.
	ErrRateLimitCapacity = errors.New("service: rate limit capacity reached")
	// ErrRateLimited identifies a caller over an authentication budget.
	ErrRateLimited = errors.New("service: rate limited")
)

// RateLimitConfig controls one fixed-window budget shared by independent keys.
type RateLimitConfig struct {
	Limit   int
	Window  time.Duration
	MaxKeys int
}

// DefaultAuthenticationRateLimitConfig is a bounded baseline for auth actions.
var DefaultAuthenticationRateLimitConfig = RateLimitConfig{
	Limit:   10,
	Window:  time.Minute,
	MaxKeys: 10_000,
}

// RateLimitDecision reports the result and remaining budget for one key.
type RateLimitDecision struct {
	Allowed    bool
	Remaining  int
	RetryAfter time.Duration
}

// RateLimitError carries retry timing without exposing the limited key.
type RateLimitError struct {
	RetryAfter time.Duration
}

func (e RateLimitError) Error() string {
	return ErrRateLimited.Error()
}

func (e RateLimitError) Unwrap() error {
	return ErrRateLimited
}

type rateLimitBucket struct {
	started time.Time
	count   int
}

// RateLimiter implements bounded, concurrent fixed-window budgets. Action is
// part of every key, so sign-in and other authentication actions stay separate.
type RateLimiter struct {
	mu      sync.Mutex
	config  RateLimitConfig
	now     func() time.Time
	buckets map[string]rateLimitBucket
}

// NewRateLimiter constructs a bounded in-memory limiter.
func NewRateLimiter(config RateLimitConfig) (*RateLimiter, error) {
	if config.Limit <= 0 || config.Window <= 0 || config.MaxKeys <= 0 {
		return nil, ErrInvalidRateLimitConfig
	}
	return &RateLimiter{
		config:  config,
		now:     time.Now,
		buckets: make(map[string]rateLimitBucket),
	}, nil
}

// Allow consumes one attempt from action/key budget.
func (l *RateLimiter) Allow(action, key string) (RateLimitDecision, error) {
	if l == nil || l.now == nil || l.buckets == nil {
		return RateLimitDecision{}, ErrInvalidRateLimitConfig
	}
	if err := validateRateLimitKey(action); err != nil {
		return RateLimitDecision{}, err
	}
	if err := validateRateLimitKey(key); err != nil {
		return RateLimitDecision{}, err
	}

	compositeKey := action + "\x00" + key
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	l.pruneExpired(now)
	bucket, exists := l.buckets[compositeKey]
	if !exists {
		if len(l.buckets) >= l.config.MaxKeys {
			return RateLimitDecision{}, ErrRateLimitCapacity
		}
		bucket = rateLimitBucket{started: now}
	}
	if now.Sub(bucket.started) >= l.config.Window {
		bucket = rateLimitBucket{started: now}
	}
	if bucket.count >= l.config.Limit {
		return RateLimitDecision{
			Allowed:    false,
			Remaining:  0,
			RetryAfter: l.config.Window - now.Sub(bucket.started),
		}, nil
	}
	bucket.count++
	l.buckets[compositeKey] = bucket
	return RateLimitDecision{
		Allowed:   true,
		Remaining: l.config.Limit - bucket.count,
	}, nil
}

// Clear removes one action/key budget, allowing successful authentication to
// reset relevant failed-attempt state.
func (l *RateLimiter) Clear(action, key string) error {
	if l == nil || l.buckets == nil {
		return ErrInvalidRateLimitConfig
	}
	if err := validateRateLimitKey(action); err != nil {
		return err
	}
	if err := validateRateLimitKey(key); err != nil {
		return err
	}
	l.mu.Lock()
	delete(l.buckets, action+"\x00"+key)
	l.mu.Unlock()
	return nil
}

func (l *RateLimiter) pruneExpired(now time.Time) {
	for key, bucket := range l.buckets {
		if now.Sub(bucket.started) >= l.config.Window {
			delete(l.buckets, key)
		}
	}
}

func validateRateLimitKey(value string) error {
	if strings.TrimSpace(value) == "" || len(value) > maxRateLimitKeyLength || strings.ContainsAny(value, "\x00\r\n") {
		return ErrInvalidRateLimitKey
	}
	return nil
}

// RateLimitedSignInService applies independent identifier and origin budgets
// around password sign-in.
type RateLimitedSignInService struct {
	signIn  *SignInService
	limiter *RateLimiter
}

// NewRateLimitedSignInService decorates sign-in with authentication budgets.
func NewRateLimitedSignInService(signIn *SignInService, limiter *RateLimiter) (*RateLimitedSignInService, error) {
	if signIn == nil {
		return nil, errors.New("service: nil signin service")
	}
	if limiter == nil {
		return nil, ErrInvalidRateLimitConfig
	}
	return &RateLimitedSignInService{signIn: signIn, limiter: limiter}, nil
}

// SignIn applies per-origin and per-normalized-identifier limits before
// delegating authentication. Successful authentication clears both budgets.
func (s *RateLimitedSignInService) SignIn(ctx context.Context, input SignInInput, origin string) (SignInResult, error) {
	if s == nil || s.signIn == nil || s.limiter == nil {
		return SignInResult{}, ErrInvalidRateLimitConfig
	}
	originDecision, err := s.limiter.Allow(signInOriginAction, origin)
	if err != nil {
		return SignInResult{}, err
	}
	if !originDecision.Allowed {
		return SignInResult{}, RateLimitError{RetryAfter: originDecision.RetryAfter}
	}
	identifier, _, identifierErr := normalizeSignInIdentifier(input.Identifier)
	if identifierErr != nil {
		_, err := s.signIn.SignIn(ctx, input)
		return SignInResult{}, err
	}
	identifierDecision, err := s.limiter.Allow(signInIdentifierAction, identifier)
	if err != nil {
		return SignInResult{}, err
	}
	if !identifierDecision.Allowed {
		return SignInResult{}, RateLimitError{RetryAfter: identifierDecision.RetryAfter}
	}
	result, err := s.signIn.SignIn(ctx, input)
	if err != nil {
		return SignInResult{}, err
	}
	if err := s.limiter.Clear(signInOriginAction, origin); err != nil {
		return SignInResult{}, fmt.Errorf("clear signin origin limit: %w", err)
	}
	if err := s.limiter.Clear(signInIdentifierAction, identifier); err != nil {
		return SignInResult{}, fmt.Errorf("clear signin identifier limit: %w", err)
	}
	return result, nil
}
