//go:build integration

package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/tewecske/goweb/internal/service"
	"github.com/tewecske/goweb/internal/store"
	"github.com/tewecske/goweb/migrations"
	testpostgres "github.com/tewecske/goweb/tests/postgres"
)

func TestUsageQueueRecordsEventsOutsideTheRequest(t *testing.T) {
	harness := testpostgres.New(t)
	runner, err := store.NewMigrator(harness.DB, migrations.FS)
	if err != nil {
		t.Fatalf("NewMigrator() error = %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := runner.Apply(ctx); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}

	repository, err := NewUsageEventRepository(harness.DB)
	if err != nil {
		t.Fatal(err)
	}
	queue, err := service.NewUsageQueue(repository, 8)
	if err != nil {
		t.Fatal(err)
	}
	runContext, stop := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- queue.Run(runContext) }()

	origin := "203.0.113.9"
	for index := 0; index < 3; index++ {
		if err := queue.EnqueueUsage(ctx, service.UsageEvent{
			Method: "GET", Route: "/{language}/groups/{id}", Status: 200, RequestID: "request-link-1", IP: &origin,
		}); err != nil {
			t.Fatalf("EnqueueUsage() error = %v", err)
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	for queue.Stats().Recorded < 3 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	stop()
	if err := <-done; err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	var (
		method    string
		route     string
		requestID string
		status    int
		count     int
	)
	if err := harness.DB.QueryRowContext(ctx, `
		SELECT COUNT(*), MIN(method), MIN(route), MIN(request_id), MIN(status) FROM usage_events
	`).Scan(&count, &method, &route, &requestID, &status); err != nil {
		t.Fatal(err)
	}
	if count != 3 || method != "GET" || route != "/{language}/groups/{id}" || requestID != "request-link-1" || status != 200 {
		t.Fatalf("stored usage = count %d method %q route %q request %q status %d", count, method, route, requestID, status)
	}
}
