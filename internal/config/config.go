// Package config loads the gateway's runtime configuration from the
// environment.
//
// Every setting has a working default, so the zero-configuration path runs
// locally. An unparseable value is an error rather than a silent fallback: a
// typo in a limit should stop startup, not quietly widen the limit.
package config

import (
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/chad3814/pg-lease-rate/internal/pgwire"
)

// envPrefix namespaces every variable this package reads.
const envPrefix = "PGLR_"

// Config is the gateway's runtime configuration.
type Config struct {
	// ListenAddr is the address the Postgres-wire listener binds to.
	ListenAddr string

	// MaxMessageBytes caps the body of a single protocol message.
	MaxMessageBytes int

	// StartupTimeout bounds the whole startup exchange, from the first byte a
	// client sends to the gateway's reply.
	StartupTimeout time.Duration

	// ShutdownTimeout bounds how long Serve waits for in-flight connections
	// after its context is cancelled.
	ShutdownTimeout time.Duration

	// LogLevel is the minimum level the default logger emits.
	LogLevel slog.Level
}

// Getenv reads an environment variable, returning the empty string when it is
// unset. os.Getenv satisfies it; tests supply a map lookup instead.
type Getenv func(name string) string

// Default returns the configuration used when nothing is set in the
// environment.
func Default() Config {
	return Config{
		ListenAddr:      ":6432",
		MaxMessageBytes: pgwire.DefaultMaxMessageBytes,
		StartupTimeout:  10 * time.Second,
		ShutdownTimeout: 10 * time.Second,
		LogLevel:        slog.LevelInfo,
	}
}

// Load builds a Config from the environment, falling back to Default for each
// unset variable. On any error the returned Config is the zero value, so a
// caller cannot mistake a partially parsed configuration for a usable one.
func Load(getenv Getenv) (Config, error) {
	cfg := Default()
	var err error

	if v := getenv(envPrefix + "LISTEN_ADDR"); v != "" {
		cfg.ListenAddr = v
	}
	if cfg.MaxMessageBytes, err = envInt(getenv, "MAX_MESSAGE_BYTES", cfg.MaxMessageBytes); err != nil {
		return Config{}, err
	}
	if cfg.StartupTimeout, err = envDuration(getenv, "STARTUP_TIMEOUT", cfg.StartupTimeout); err != nil {
		return Config{}, err
	}
	if cfg.ShutdownTimeout, err = envDuration(getenv, "SHUTDOWN_TIMEOUT", cfg.ShutdownTimeout); err != nil {
		return Config{}, err
	}
	if cfg.LogLevel, err = envLevel(getenv, "LOG_LEVEL", cfg.LogLevel); err != nil {
		return Config{}, err
	}

	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// Validate reports whether the configuration is internally usable.
func (c Config) Validate() error {
	if c.ListenAddr == "" {
		return fmt.Errorf("config: %sLISTEN_ADDR must not be empty", envPrefix)
	}
	if c.MaxMessageBytes <= 0 {
		return fmt.Errorf("config: %sMAX_MESSAGE_BYTES must be positive, got %d", envPrefix, c.MaxMessageBytes)
	}
	if c.StartupTimeout <= 0 {
		return fmt.Errorf("config: %sSTARTUP_TIMEOUT must be positive, got %s", envPrefix, c.StartupTimeout)
	}
	if c.ShutdownTimeout <= 0 {
		return fmt.Errorf("config: %sSHUTDOWN_TIMEOUT must be positive, got %s", envPrefix, c.ShutdownTimeout)
	}
	return nil
}

func envInt(getenv Getenv, name string, fallback int) (int, error) {
	raw := getenv(envPrefix + name)
	if raw == "" {
		return fallback, nil
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("config: %s%s: %w", envPrefix, name, err)
	}
	return v, nil
}

func envDuration(getenv Getenv, name string, fallback time.Duration) (time.Duration, error) {
	raw := getenv(envPrefix + name)
	if raw == "" {
		return fallback, nil
	}
	v, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("config: %s%s: %w", envPrefix, name, err)
	}
	return v, nil
}

func envLevel(getenv Getenv, name string, fallback slog.Level) (slog.Level, error) {
	raw := getenv(envPrefix + name)
	if raw == "" {
		return fallback, nil
	}
	var level slog.Level
	if err := level.UnmarshalText([]byte(strings.ToUpper(raw))); err != nil {
		return 0, fmt.Errorf("config: %s%s: %w", envPrefix, name, err)
	}
	return level, nil
}
