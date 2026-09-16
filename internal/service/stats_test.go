package service

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestNewDatastoreStatsServiceValidatesConfig(t *testing.T) {
	if _, err := NewDatastoreStatsService(nil, nil, time.Second); !errors.Is(err, ErrNilDatastoreStatsRepository) {
		t.Fatalf("NewDatastoreStatsService(nil repo) error = %v, want %v", err, ErrNilDatastoreStatsRepository)
	}
	if _, err := NewDatastoreStatsService(&datastoreStatsRepositoryStub{}, nil, -time.Second); !errors.Is(err, ErrInvalidDatastoreStatsConfig) {
		t.Fatalf("NewDatastoreStatsService(negative ttl) error = %v, want %v", err, ErrInvalidDatastoreStatsConfig)
	}
}

func TestDatastoreStatsServiceCachesAggregatesButNotLockouts(t *testing.T) {
	repository := &datastoreStatsRepositoryStub{accounts: AccountCounts{Total: 5, Guests: 2}}
	lockouts := &lockoutCounterStub{count: 1}
	service, err := NewDatastoreStatsService(repository, lockouts, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(10_000, 0)
	service.now = func() time.Time { return now }

	counts, err := service.Counts(context.Background())
	if err != nil {
		t.Fatalf("Counts() error = %v", err)
	}
	if counts.TotalAccounts != 5 || counts.CurrentLockouts != 1 {
		t.Fatalf("counts = %+v, want total 5 and lockouts 1", counts)
	}
	counts, err = service.Counts(context.Background())
	if err != nil {
		t.Fatalf("Counts() error = %v", err)
	}
	if repository.accountCalls != 1 {
		t.Fatalf("account calls = %d, want cached single call", repository.accountCalls)
	}
	lockouts.count = 3
	counts, err = service.Counts(context.Background())
	if err != nil {
		t.Fatalf("Counts() error = %v", err)
	}
	if counts.CurrentLockouts != 3 {
		t.Fatalf("lockouts = %d, want live 3", counts.CurrentLockouts)
	}
	now = now.Add(2 * time.Minute)
	if _, err := service.Counts(context.Background()); err != nil {
		t.Fatal(err)
	}
	if repository.accountCalls != 2 {
		t.Fatalf("account calls after ttl = %d, want 2", repository.accountCalls)
	}
}

func TestDatastoreStatsServicePropagatesFailures(t *testing.T) {
	backendErr := errors.New("count failed")
	service, err := NewDatastoreStatsService(&datastoreStatsRepositoryStub{err: backendErr}, nil, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Counts(context.Background()); !errors.Is(err, backendErr) {
		t.Fatalf("Counts() error = %v, want errors.Is(_, %v)", err, backendErr)
	}
}

func TestDatastoreStatsServiceRejectsNilContext(t *testing.T) {
	service, err := NewDatastoreStatsService(&datastoreStatsRepositoryStub{}, nil, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Counts(nil); err == nil {
		t.Fatal("Counts(nil) error = nil, want failure")
	}
}

func TestRateLimiterLockedCount(t *testing.T) {
	limiter, err := NewRateLimiter(RateLimitConfig{Limit: 2, Window: time.Minute, MaxKeys: 10})
	if err != nil {
		t.Fatal(err)
	}
	if locked := limiter.LockedCount(); locked != 0 {
		t.Fatalf("LockedCount() = %d, want 0", locked)
	}
	for range 2 {
		if _, err := limiter.Allow("signin.identifier", "a@example.test"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := limiter.Allow("signin.identifier", "b@example.test"); err != nil {
		t.Fatal(err)
	}
	if locked := limiter.LockedCount(); locked != 1 {
		t.Fatalf("LockedCount() = %d, want 1", locked)
	}
}

type datastoreStatsRepositoryStub struct {
	accounts     AccountCounts
	err          error
	accountCalls int
}

func (r *datastoreStatsRepositoryStub) CountAccounts(context.Context) (AccountCounts, error) {
	r.accountCalls++
	if r.err != nil {
		return AccountCounts{}, r.err
	}
	return r.accounts, nil
}

func (r *datastoreStatsRepositoryStub) CountActiveSessions(context.Context, int64) (int, error) {
	return 0, r.err
}

func (r *datastoreStatsRepositoryStub) CountExpiredSessions(context.Context, int64) (int, error) {
	return 0, r.err
}

func (r *datastoreStatsRepositoryStub) CountExpiredEmailTokens(context.Context, int64) (int, error) {
	return 0, r.err
}

func (r *datastoreStatsRepositoryStub) CountExpiredPasswordResetTokens(context.Context, int64) (int, error) {
	return 0, r.err
}

func (r *datastoreStatsRepositoryStub) CountExpiredOAuthStates(context.Context, int64) (int, error) {
	return 0, r.err
}

func (r *datastoreStatsRepositoryStub) CountRecentFailedSignIns(context.Context, int64) (int, error) {
	return 0, r.err
}

type lockoutCounterStub struct {
	count int
}

func (s *lockoutCounterStub) LockedCount() int { return s.count }
