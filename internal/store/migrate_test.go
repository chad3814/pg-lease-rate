package store

import (
	"io/fs"
	"strings"
	"testing"
)

func TestMigrationsAreEmbedded(t *testing.T) {
	entries, err := fs.ReadDir(Migrations, MigrationsDir)
	if err != nil {
		t.Fatalf("ReadDir(%q): %v", MigrationsDir, err)
	}
	if len(entries) == 0 {
		t.Fatalf("no migrations embedded under %q", MigrationsDir)
	}

	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".sql") {
			t.Errorf("unexpected non-SQL file embedded: %s", e.Name())
		}
		body, err := fs.ReadFile(Migrations, MigrationsDir+"/"+e.Name())
		if err != nil {
			t.Fatalf("ReadFile(%s): %v", e.Name(), err)
		}
		// goose needs both directions in every file.
		for _, want := range []string{"-- +goose Up", "-- +goose Down"} {
			if !strings.Contains(string(body), want) {
				t.Errorf("%s is missing %q", e.Name(), want)
			}
		}
	}

	// ExpectedVersion must match the number of migrations on disk, or the
	// startup check will reject a correctly migrated database.
	if int(ExpectedVersion) != len(entries) {
		t.Errorf("ExpectedVersion = %d but %d migrations are embedded; bump the constant",
			ExpectedVersion, len(entries))
	}
}

func TestCheckSchemaRejectsBadURL(t *testing.T) {
	if err := CheckSchema(t.Context(), "not://a valid url"); err == nil {
		t.Error("CheckSchema() = nil error, want a connection failure")
	}
}
