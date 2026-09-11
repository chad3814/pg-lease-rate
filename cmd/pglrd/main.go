// Command pglrd runs the pg-lease-rate gateway.
//
// Configuration comes from the environment; see internal/config and
// .env.example. Startup verifies that the metadata database is migrated to the
// schema version this build expects, then serves until it receives SIGINT or
// SIGTERM, then drains in-flight connections before exiting.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/chad3814/pg-lease-rate/internal/config"
	"github.com/chad3814/pg-lease-rate/internal/gateway"
	"github.com/chad3814/pg-lease-rate/internal/store"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "pglrd: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		return err
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: cfg.LogLevel,
	}))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Refuse to serve against a schema this build does not understand.
	// Migrations are applied by pglr-migrate, not here.
	if err := store.CheckSchema(ctx, cfg.DatabaseURL); err != nil {
		return err
	}

	return gateway.New(cfg, logger).ListenAndServe(ctx)
}
