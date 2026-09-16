package service

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestAuditServiceRecordStoresValidatedEntry(t *testing.T) {
	repository := &auditRepositoryStub{}
	audit, err := NewAuditService(repository)
	if err != nil {
		t.Fatalf("NewAuditService() error = %v", err)
	}
	if err := audit.Record(context.Background(), AuditRecord{
		ActorUserID: 7,
		ActorEmail:  "admin@example.test",
		Action:      AuditActionAccountCreated,
		TargetType:  "user",
		TargetID:    "42",
		Detail:      "created account",
		IP:          "203.0.113.7",
	}); err != nil {
		t.Fatalf("Record() error = %v", err)
	}
	if len(repository.entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(repository.entries))
	}
	entry := repository.entries[0]
	if entry.Action != AuditActionAccountCreated || entry.OccurredAt <= 0 {
		t.Fatalf("entry = %+v, want action and timestamp", entry)
	}
	if entry.ActorUserID == nil || *entry.ActorUserID != 7 {
		t.Fatalf("actor = %v, want 7", entry.ActorUserID)
	}
	if entry.ActorEmail == nil || *entry.ActorEmail != "admin@example.test" {
		t.Fatalf("actor email = %v, want snapshot", entry.ActorEmail)
	}
}

func TestAuditServiceRecordRejectsInvalidInput(t *testing.T) {
	tests := []struct {
		name   string
		record AuditRecord
	}{
		{name: "missing actor", record: AuditRecord{Action: "x"}},
		{name: "missing action", record: AuditRecord{ActorUserID: 1}},
		{name: "control characters", record: AuditRecord{ActorUserID: 1, Action: "bad\naction"}},
		{name: "oversized detail", record: AuditRecord{ActorUserID: 1, Action: "ok", Detail: strings.Repeat("a", 1001)}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			audit, err := NewAuditService(&auditRepositoryStub{})
			if err != nil {
				t.Fatalf("NewAuditService() error = %v", err)
			}
			if err := audit.Record(context.Background(), test.record); !errors.Is(err, ErrInvalidAuditEntry) {
				t.Fatalf("Record() error = %v, want %v", err, ErrInvalidAuditEntry)
			}
		})
	}
}

func TestAuditServiceRecordPropagatesStorageFailure(t *testing.T) {
	failure := errors.New("storage down")
	audit, err := NewAuditService(&auditRepositoryStub{err: failure})
	if err != nil {
		t.Fatalf("NewAuditService() error = %v", err)
	}
	err = audit.Record(context.Background(), AuditRecord{ActorUserID: 1, Action: "ok"})
	if !errors.Is(err, failure) {
		t.Fatalf("Record() error = %v, want %v", err, failure)
	}
}

func TestNewAuditServiceRejectsNilRepository(t *testing.T) {
	if _, err := NewAuditService(nil); !errors.Is(err, ErrNilAuditRepository) {
		t.Fatalf("error = %v, want %v", err, ErrNilAuditRepository)
	}
}

type auditRepositoryStub struct {
	entries []AuditEntry
	err     error
}

func (s *auditRepositoryStub) CreateAuditEntry(_ context.Context, entry AuditEntry) error {
	if s.err != nil {
		return s.err
	}
	s.entries = append(s.entries, entry)
	return nil
}

func TestAuditServiceRecordEmitsToSink(t *testing.T) {
	sink := &auditSinkStub{}
	audit, err := NewAuditService(&auditRepositoryStub{})
	if err != nil {
		t.Fatalf("NewAuditService() error = %v", err)
	}
	audit.SetSink(sink)
	record := AuditRecord{ActorUserID: 1, Action: AuditActionAccountCreated, TargetID: "9", Detail: "user@example.test"}
	if err := audit.Record(context.Background(), record); err != nil {
		t.Fatalf("Record() error = %v", err)
	}
	if len(sink.records) != 1 || sink.records[0].Action != AuditActionAccountCreated {
		t.Fatalf("sink records = %+v, want one account-created record", sink.records)
	}
}

func TestAuditServiceSinkFailureDoesNotUndoStoredRecord(t *testing.T) {
	repository := &auditRepositoryStub{}
	audit, err := NewAuditService(repository)
	if err != nil {
		t.Fatalf("NewAuditService() error = %v", err)
	}
	audit.SetSink(erroringAuditSink{})
	if err := audit.Record(context.Background(), AuditRecord{ActorUserID: 1, Action: "x"}); err != nil {
		t.Fatalf("Record() error = %v, want nil", err)
	}
	if len(repository.entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(repository.entries))
	}
}

type auditSinkStub struct {
	records []AuditRecord
}

func (s *auditSinkStub) AuditRecorded(_ context.Context, record AuditRecord) {
	s.records = append(s.records, record)
}

type erroringAuditSink struct{}

func (erroringAuditSink) AuditRecorded(context.Context, AuditRecord) {}
