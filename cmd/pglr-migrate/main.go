// Command pglr-migrate applies pg-lease-rate's schema migrations.
//
// Migrations are a deploy step, not a server startup side effect: pglrd only
// verifies the applied version and refuses to start on a mismatch. That way a
// bad migration fails a deploy instead of taking the service down, and
// several gateways booting at once cannot race.
//
// This is the only command that imports goose.
package main

import (
	"database/sql"
	"errors"
	"fmt"
	"os"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"github.com/chad3814/pg-lease-rate/internal/config"
	"github.com/chad3814/pg-lease-rate/internal/store"
)

const usage = `usage: pglr-migrate <up|down|status|version>

  up       apply every pending migration
  down     roll back the most recent migration
  status   print each migration and whether it is applied
  version  print the currently applied version

The database is read from PGLR_DATABASE_URL.
`

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "pglr-migrate: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) != 1 {
		fmt.Fprint(os.Stderr, usage)
		return errors.New("expected exactly one subcommand")
	}

	cfg, err := config.Load(os.Getenv)
	if err != nil {
		return err
	}

	db, err := sql.Open("pgx", cfg.DatabaseURL)
	if err != nil {
		return fmt.Errorf("open %s: %w", cfg.DatabaseURL, err)
	}
	defer func() {
		_ = db.Close()
	}()

	goose.SetBaseFS(store.Migrations)
	if err := goose.SetDialect("postgres"); err != nil {
		return fmt.Errorf("select dialect: %w", err)
	}

	switch args[0] {
	case "up":
		return goose.Up(db, store.MigrationsDir)
	case "down":
		return goose.Down(db, store.MigrationsDir)
	case "status":
		return goose.Status(db, store.MigrationsDir)
	case "version":
		v, err := goose.GetDBVersion(db)
		if err != nil {
			return err
		}
		fmt.Printf("%d\n", v)
		return nil
	default:
		fmt.Fprint(os.Stderr, usage)
		return fmt.Errorf("unknown subcommand %q", args[0])
	}
}
