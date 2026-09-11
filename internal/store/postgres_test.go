//go:build integration

package store

import (
	"context"
	"os"
	"testing"
)

// testDatabaseURL is the database the integration suite runs against.
func testDatabaseURL() string {
	if v := os.Getenv("PGLR_TEST_DATABASE_URL"); v != "" {
		return v
	}
	if v := os.Getenv("PGLR_DATABASE_URL"); v != "" {
		return v
	}
	return "postgres://postgres:postgres@127.0.0.1:5432/pglr?sslmode=disable"
}

func TestPostgresConformance(t *testing.T) {
	ctx := context.Background()

	// Opened once and shared. Failing rather than skipping is deliberate:
	// passing -tags integration is an explicit request for these tests, and a
	// silent skip is how integration suites rot.
	pg, err := NewPostgres(ctx, testDatabaseURL())
	if err != nil {
		t.Fatalf("NewPostgres(%s): %v\nis the database up and migrated? try: make up && make migrate",
			testDatabaseURL(), err)
	}
	t.Cleanup(pg.Close)

	runConformance(t, func(t *testing.T) testStore {
		t.Helper()
		if _, err := pg.pool.Exec(ctx, `TRUNCATE leases, tenants CASCADE`); err != nil {
			t.Fatalf("truncate: %v", err)
		}
		return pg
	})
}

func TestPostgresRejectsBadURL(t *testing.T) {
	if _, err := NewPostgres(context.Background(), "not://a valid url"); err == nil {
		t.Error("NewPostgres() = nil error, want a parse failure")
	}
}
