// Command pglrd runs the pg-lease-rate gateway.
//
// Configuration comes from the environment; see internal/config and
// .env.example. The process serves until it receives SIGINT or SIGTERM, then
// drains in-flight connections before exiting.
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

	return gateway.New(cfg, logger).ListenAndServe(ctx)
}
