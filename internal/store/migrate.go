package store

import (
	"context"
	"embed"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Migrations holds the schema migrations, embedded so that cmd/pglr-migrate
// is a self-contained binary.
//
//go:embed migrations/*.sql
var Migrations embed.FS

// MigrationsDir is the path within Migrations that goose reads.
const MigrationsDir = "migrations"

// ExpectedVersion is the schema version this build requires. Bump it with
// every migration added.
const ExpectedVersion int64 = 1

// CheckSchema verifies that databaseURL is migrated to ExpectedVersion.
//
// It opens a single connection rather than a pool, and reads the version with
// a plain query rather than calling into goose, so that the gateway never
// links the migration library.
//
// Any mismatch is ErrSchemaVersion, in both directions: a database behind this
// build needs migrating, and a database ahead of it means an old binary is
// running against a new schema. The message says which.
func CheckSchema(ctx context.Context, databaseURL string) error {
	conn, err := pgx.Connect(ctx, databaseURL)
	if err != nil {
		return fmt.Errorf("store: connect to verify schema: %w", err)
	}
	defer func() {
		_ = conn.Close(ctx)
	}()

	// goose's own GetLatestVersion query. There is no is_applied filter
	// because goose down deletes the row rather than clearing the flag.
	const q = `SELECT max(version_id) FROM goose_db_version`

	var applied *int64
	if err := conn.QueryRow(ctx, q).Scan(&applied); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == sqlStateUndefinedTable {
			return fmt.Errorf("%w: the database has never been migrated; run: make migrate", ErrSchemaVersion)
		}
		return fmt.Errorf("store: read schema version: %w", err)
	}

	switch {
	case applied == nil:
		return fmt.Errorf("%w: no migrations are applied; run: make migrate", ErrSchemaVersion)
	case *applied < ExpectedVersion:
		return fmt.Errorf("%w: database is at %d, this build needs %d; run: make migrate",
			ErrSchemaVersion, *applied, ExpectedVersion)
	case *applied > ExpectedVersion:
		return fmt.Errorf("%w: database is at %d but this build only knows %d; deploy a newer binary",
			ErrSchemaVersion, *applied, ExpectedVersion)
	}
	return nil
}
