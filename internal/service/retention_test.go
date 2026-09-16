package service

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestNewRetentionServiceValidatesConfig(t *testing.T) {
	if _, err := NewRetentionService(nil, time.Hour, time.Hour); !errors.Is(err, ErrNilRetentionRepository) {
		t.Fatalf("NewRetentionService(nil repo) error = %v, want %v", err, ErrNilRetentionRepository)
	}
	if _, err := NewRetentionService(&retentionRepositoryStub{}, 0, time.Hour); !errors.Is(err, ErrInvalidRetentionConfig) {
		t.Fatalf("NewRetentionService(zero login) error = %v, want %v", err, ErrInvalidRetentionConfig)
	}
	if _, err := NewRetentionService(&retentionRepositoryStub{}, time.Hour, -time.Second); !errors.Is(err, ErrInvalidRetentionConfig) {
		t.Fatalf("NewRetentionService(negative usage) error = %v, want %v", err, ErrInvalidRetentionConfig)
	}
}

func TestRetentionCleanupTokensUsesSingleCurrentTime(t *testing.T) {
	repo := &retentionRepositoryStub{counts: []int{2, 3, 1}}
	service, err := NewRetentionService(repo, time.Hour, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	service.now = func() time.Time { return time.Unix(50_000, 0) }

	removed, err := service.CleanupTokens(context.Background())
	if err != nil {
		t.Fatalf("CleanupTokens() error = %v", err)
	}
	if removed != 6 {
		t.Fatalf("CleanupTokens() removed = %d, want 6", removed)
	}
	for index, cutoff := range repo.tokenCutoffs {
		if cutoff != 50_000 {
			t.Fatalf("token cutoff %d = %d, want 50000", index, cutoff)
		}
	}
}

func TestRetentionCleanupAppliesConfiguredCutoffs(t *testing.T) {
	repo := &retentionRepositoryStub{counts: []int{4}}
	service, err := NewRetentionService(repo, 48*time.Hour, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	service.now = func() time.Time { return time.Unix(100_000, 0) }

	removed, err := service.CleanupLoginAttempts(context.Background())
	if err != nil {
		t.Fatalf("CleanupLoginAttempts() error = %v", err)
	}
	if removed != 4 || repo.loginCutoff != 100_000-int64((48*time.Hour)/time.Second) {
		t.Fatalf("login cleanup = %d/%d, want 4/%d", removed, repo.loginCutoff, 100_000-int64((48*time.Hour)/time.Second))
	}

	service.repository.(*retentionRepositoryStub).counts = []int{7}
	service.repository.(*retentionRepositoryStub).calls = 0
	removed, err = service.CleanupUsageEvents(context.Background())
	if err != nil {
		t.Fatalf("CleanupUsageEvents() error = %v", err)
	}
	if removed != 7 || repo.usageCutoff != 100_000-int64((24*time.Hour)/time.Second) {
		t.Fatalf("usage cleanup = %d/%d, want 7/%d", removed, repo.usageCutoff, 100_000-int64((24*time.Hour)/time.Second))
	}
}

func TestRetentionCleanupStopsOnRepositoryFailure(t *testing.T) {
	backendErr := errors.New("delete failed")
	repo := &retentionRepositoryStub{counts: []int{5, 0, 0}, errAt: 1, err: backendErr}
	service, err := NewRetentionService(repo, time.Hour, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.CleanupTokens(context.Background()); !errors.Is(err, backendErr) {
		t.Fatalf("CleanupTokens() error = %v, want errors.Is(_, %v)", err, backendErr)
	}
	if repo.calls != 2 {
		t.Fatalf("repository calls = %d, want stop after first failure", repo.calls)
	}
}

func TestRetentionServiceRejectsNilContext(t *testing.T) {
	service, err := NewRetentionService(&retentionRepositoryStub{}, time.Hour, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.CleanupTokens(nil); err == nil {
		t.Fatal("CleanupTokens(nil) error = nil, want failure")
	}
}

func TestRetentionServiceReportsPeriods(t *testing.T) {
	service, err := NewRetentionService(&retentionRepositoryStub{}, 48*time.Hour, 72*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if service.LoginRetention() != 48*time.Hour || service.UsageRetention() != 72*time.Hour {
		t.Fatalf("periods = %s/%s, want 48h/72h", service.LoginRetention(), service.UsageRetention())
	}
}

type retentionRepositoryStub struct {
	counts       []int
	tokenCutoffs []int64
	loginCutoff  int64
	usageCutoff  int64
	calls        int
	errAt        int
	err          error
}

func (r *retentionRepositoryStub) next() (int, error) {
	index := r.calls
	r.calls++
	if r.err != nil && r.errAt == index {
		return 0, r.err
	}
	if index < len(r.counts) {
		return r.counts[index], nil
	}
	return 0, nil
}

func (r *retentionRepositoryStub) DeleteExpiredEmailConfirmationTokens(_ context.Context, cutoff int64) (int, error) {
	r.tokenCutoffs = append(r.tokenCutoffs, cutoff)
	return r.next()
}

func (r *retentionRepositoryStub) DeleteExpiredPasswordResetTokens(_ context.Context, cutoff int64) (int, error) {
	r.tokenCutoffs = append(r.tokenCutoffs, cutoff)
	return r.next()
}

func (r *retentionRepositoryStub) DeleteExpiredOAuthStates(_ context.Context, cutoff int64) (int, error) {
	r.tokenCutoffs = append(r.tokenCutoffs, cutoff)
	return r.next()
}

func (r *retentionRepositoryStub) DeleteLoginAttemptsBefore(_ context.Context, cutoff int64) (int, error) {
	r.loginCutoff = cutoff
	return r.next()
}

func (r *retentionRepositoryStub) DeleteUsageEventsBefore(_ context.Context, cutoff int64) (int, error) {
	r.usageCutoff = cutoff
	return r.next()
}
