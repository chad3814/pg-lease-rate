package store

import "embed"

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
