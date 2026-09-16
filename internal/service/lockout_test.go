package service

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestRateLimiterSnapshotDoesNotConsume(t *testing.T) {
	limiter, err := NewRateLimiter(RateLimitConfig{Limit: 2, Window: time.Minute, MaxKeys: 10})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := limiter.Snapshot("signin", "user@example.com")
	if err != nil {
		t.Fatalf("Snapshot() error = %v", err)
	}
	if snapshot.Count != 0 || snapshot.Limit != 2 {
		t.Fatalf("snapshot = %+v, want count 0 limit 2", snapshot)
	}
	if _, err := limiter.Allow("signin", "user@example.com"); err != nil {
		t.Fatal(err)
	}
	snapshot, err = limiter.Snapshot("signin", "user@example.com")
	if err != nil {
		t.Fatalf("Snapshot() error = %v", err)
	}
	if snapshot.Count != 1 {
		t.Fatalf("snapshot count = %d, want 1", snapshot.Count)
	}
}

func TestLockoutServiceStatusReportsLockedIdentifierAndOrigins(t *testing.T) {
	limiter, err := NewRateLimiter(RateLimitConfig{Limit: 2, Window: time.Minute, MaxKeys: 100})
	if err != nil {
		t.Fatal(err)
	}
	email := "locked@example.test"
	username := "locked"
	// Fill the identifier budget to the limit.
	for range 2 {
		if _, err := limiter.Allow(signInIdentifierAction, email); err != nil {
			t.Fatal(err)
		}
	}
	origin := "203.0.113.9"
	if _, err := limiter.Allow(signInOriginAction, origin); err != nil {
		t.Fatal(err)
	}
	attempts := &loginAttemptRepositoryStub{listedByEmail: []LoginAttempt{{ID: 1, Email: email, IP: &origin, Outcome: LoginOutcomeInvalidCredentials, CreatedAt: 100}}}
	service, err := NewLockoutService(limiter, attempts, &auditRecorderStub{})
	if err != nil {
		t.Fatal(err)
	}

	status, err := service.Status(context.Background(), User{ID: 9, Email: &email, Username: &username})
	if err != nil {
		t.Fatalf("Status() error = %v", err)
	}
	if !status.Locked || status.IdentifierCount != 2 || status.IdentifierLimit != 2 {
		t.Fatalf("status = %+v, want locked identifier 2/2", status)
	}
	if len(status.Origins) != 1 || status.Origins[0].Key != origin || status.Origins[0].Count != 1 {
		t.Fatalf("origins = %+v, want one origin with count 1", status.Origins)
	}
}

func TestLockoutServiceClearRemovesAllDimensions(t *testing.T) {
	limiter, err := NewRateLimiter(RateLimitConfig{Limit: 2, Window: time.Minute, MaxKeys: 100})
	if err != nil {
		t.Fatal(err)
	}
	email := "clear@example.test"
	origin := "198.51.100.7"
	for range 2 {
		if _, err := limiter.Allow(signInIdentifierAction, email); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := limiter.Allow(signInOriginAction, origin); err != nil {
		t.Fatal(err)
	}
	attempts := &loginAttemptRepositoryStub{listedByEmail: []LoginAttempt{{ID: 1, Email: email, IP: &origin, Outcome: LoginOutcomeInvalidCredentials, CreatedAt: 100}}}
	auditor := &auditRecorderStub{}
	service, err := NewLockoutService(limiter, attempts, auditor)
	if err != nil {
		t.Fatal(err)
	}
	target := User{ID: 9, Email: &email}
	if err := service.Clear(context.Background(), AdminActionContext{ActorID: 1}, target); err != nil {
		t.Fatalf("Clear() error = %v", err)
	}
	status, err := service.Status(context.Background(), target)
	if err != nil {
		t.Fatalf("Status() error = %v", err)
	}
	if status.Locked || status.IdentifierCount != 0 {
		t.Fatalf("status after clear = %+v, want unlocked zero count", status)
	}
	for _, originStatus := range status.Origins {
		if originStatus.Count != 0 {
			t.Fatalf("origin after clear = %+v, want zero count", originStatus)
		}
	}
	if len(auditor.records) != 1 || auditor.records[0].Action != AuditActionLockoutCleared {
		t.Fatalf("audit records = %+v, want lockout-cleared", auditor.records)
	}
}

func TestNewLockoutServiceRejectsMissingPorts(t *testing.T) {
	if _, err := NewLockoutService(nil, &loginAttemptRepositoryStub{}, nil); !errors.Is(err, ErrNilLockoutService) {
		t.Fatalf("error = %v, want %v", err, ErrNilLockoutService)
	}
	limiter, _ := NewRateLimiter(RateLimitConfig{Limit: 1, Window: time.Minute, MaxKeys: 1})
	if _, err := NewLockoutService(limiter, nil, nil); !errors.Is(err, ErrNilLockoutService) {
		t.Fatalf("error = %v, want %v", err, ErrNilLockoutService)
	}
}
