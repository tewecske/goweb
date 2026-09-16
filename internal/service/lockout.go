package service

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"
)

// MaxLockoutOrigins bounds how many recent origins a diagnostic page inspects.
const MaxLockoutOrigins = 10

var (
	// ErrNilLockoutService identifies missing lockout diagnostics wiring.
	ErrNilLockoutService = errors.New("service: nil lockout service")
)

// LockoutLimiter inspects and clears live rate-limit budgets.
type LockoutLimiter interface {
	Snapshot(action, key string) (RateLimitSnapshot, error)
	Clear(action, key string) error
}

// LockoutOrigin is one recent request origin's current budget.
type LockoutOrigin struct {
	Key        string
	Count      int
	Limit      int
	RetryAfter time.Duration
}

// LockoutStatus is the live lockout state for one account.
type LockoutStatus struct {
	IdentifierKey        string
	IdentifierCount      int
	IdentifierLimit      int
	IdentifierRetryAfter time.Duration
	Locked               bool
	Origins              []LockoutOrigin
}

// LockoutService reads and clears live lockout state for an account. Rate-limit
// buckets are live process state; they are not stored in the database.
type LockoutService struct {
	limiter  LockoutLimiter
	attempts LoginAttemptRepository
	auditor  AuditRecorder
}

// NewLockoutService constructs lockout diagnostics with explicit limiter,
// history, and audit dependencies.
func NewLockoutService(limiter LockoutLimiter, attempts LoginAttemptRepository, auditor AuditRecorder) (*LockoutService, error) {
	if limiter == nil || attempts == nil {
		return nil, ErrNilLockoutService
	}
	return &LockoutService{limiter: limiter, attempts: attempts, auditor: auditor}, nil
}

// Status returns the account identifier budget plus the budgets of the origins
// that recently attempted sign-in for the account's email.
func (s *LockoutService) Status(ctx context.Context, target User) (LockoutStatus, error) {
	if s == nil || s.limiter == nil || s.attempts == nil {
		return LockoutStatus{}, ErrNilLockoutService
	}
	if ctx == nil {
		return LockoutStatus{}, errors.New("service: nil lockout context")
	}
	status := LockoutStatus{IdentifierLimit: s.identifierLimit()}
	for _, key := range signInIdentifierKeys(target) {
		snapshot, err := s.limiter.Snapshot(signInIdentifierAction, key)
		if err != nil {
			return LockoutStatus{}, err
		}
		if snapshot.Count == 0 || snapshot.Count < status.IdentifierCount {
			continue
		}
		status.IdentifierKey = key
		status.IdentifierCount = snapshot.Count
		status.IdentifierLimit = snapshot.Limit
		status.IdentifierRetryAfter = snapshot.RetryAfter
		status.Locked = snapshot.Limit > 0 && snapshot.Count >= snapshot.Limit
	}

	for _, origin := range s.recentOrigins(ctx, target) {
		snapshot, err := s.limiter.Snapshot(signInOriginAction, origin)
		if err != nil {
			return LockoutStatus{}, err
		}
		status.Origins = append(status.Origins, LockoutOrigin{
			Key:        origin,
			Count:      snapshot.Count,
			Limit:      snapshot.Limit,
			RetryAfter: snapshot.RetryAfter,
		})
	}
	return status, nil
}

// Clear removes every identifier and recent-origin budget for an account and
// records the action. Clearing an already clear account is a successful no-op.
func (s *LockoutService) Clear(ctx context.Context, actor AdminActionContext, target User) error {
	if s == nil || s.limiter == nil || s.attempts == nil {
		return ErrNilLockoutService
	}
	if ctx == nil {
		return errors.New("service: nil lockout context")
	}
	if actor.ActorID <= 0 || target.ID <= 0 {
		return ErrInvalidAdminQuery
	}
	for _, key := range signInIdentifierKeys(target) {
		if err := s.limiter.Clear(signInIdentifierAction, key); err != nil {
			return err
		}
	}
	for _, origin := range s.recentOrigins(ctx, target) {
		if err := s.limiter.Clear(signInOriginAction, origin); err != nil {
			return err
		}
	}
	if s.auditor == nil {
		return nil
	}
	record := AuditRecord{
		ActorUserID: actor.ActorID,
		Action:      AuditActionLockoutCleared,
		TargetType:  "user",
		TargetID:    strconv.FormatInt(target.ID, 10),
		Detail:      adminAccountDetail(target),
		IP:          actor.Origin,
	}
	_ = s.auditor.Record(ctx, record)
	return nil
}

func (s *LockoutService) recentOrigins(ctx context.Context, target User) []string {
	if target.Email == nil || strings.TrimSpace(*target.Email) == "" {
		return nil
	}
	attempts, err := s.attempts.ListLoginAttemptsForEmail(ctx, *target.Email, MaxAdminLoginAttempts)
	if err != nil {
		return nil
	}
	seen := make(map[string]struct{}, MaxLockoutOrigins)
	origins := make([]string, 0, MaxLockoutOrigins)
	for _, attempt := range attempts {
		if attempt.IP == nil {
			continue
		}
		origin := strings.TrimSpace(*attempt.IP)
		if origin == "" {
			continue
		}
		if _, ok := seen[origin]; ok {
			continue
		}
		seen[origin] = struct{}{}
		origins = append(origins, origin)
		if len(origins) >= MaxLockoutOrigins {
			break
		}
	}
	return origins
}

func (s *LockoutService) identifierLimit() int {
	snapshot, err := s.limiter.Snapshot(signInIdentifierAction, "probe")
	if err != nil {
		return 0
	}
	return snapshot.Limit
}

func signInIdentifierKeys(target User) []string {
	var keys []string
	if target.Email != nil && strings.TrimSpace(*target.Email) != "" {
		keys = append(keys, strings.TrimSpace(*target.Email))
	}
	if target.Username != nil && strings.TrimSpace(*target.Username) != "" {
		keys = append(keys, strings.TrimSpace(*target.Username))
	}
	return keys
}
