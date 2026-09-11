package config

import (
	"log/slog"
	"strings"
	"testing"
	"time"
)

// env returns a Getenv backed by a map, so tests never mutate process state.
func env(m map[string]string) Getenv {
	return func(name string) string { return m[name] }
}

func TestLoad(t *testing.T) {
	tests := []struct {
		name string
		env  map[string]string
		want Config
	}{
		{
			name: "empty environment yields defaults",
			env:  nil,
			want: Default(),
		},
		{
			name: "empty values fall back to defaults",
			env: map[string]string{
				envPrefix + "LISTEN_ADDR":       "",
				envPrefix + "MAX_MESSAGE_BYTES": "",
				envPrefix + "STARTUP_TIMEOUT":   "",
				envPrefix + "LOG_LEVEL":         "",
			},
			want: Default(),
		},
		{
			name: "every setting overridden",
			env: map[string]string{
				envPrefix + "LISTEN_ADDR":       "127.0.0.1:15432",
				envPrefix + "DATABASE_URL":      "postgres://u@h:5/d",
				envPrefix + "MAX_MESSAGE_BYTES": "1048576",
				envPrefix + "STARTUP_TIMEOUT":   "3s",
				envPrefix + "SHUTDOWN_TIMEOUT":  "1m30s",
				envPrefix + "LOG_LEVEL":         "debug",
			},
			want: Config{
				ListenAddr:      "127.0.0.1:15432",
				DatabaseURL:     "postgres://u@h:5/d",
				MaxMessageBytes: 1 << 20,
				StartupTimeout:  3 * time.Second,
				ShutdownTimeout: 90 * time.Second,
				LogLevel:        slog.LevelDebug,
			},
		},
		{
			name: "log level is case insensitive",
			env:  map[string]string{envPrefix + "LOG_LEVEL": "WaRn"},
			want: func() Config {
				c := Default()
				c.LogLevel = slog.LevelWarn
				return c
			}(),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Load(env(tc.env))
			if err != nil {
				t.Fatalf("Load() unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("Load() = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestLoadRejectsBadValues(t *testing.T) {
	tests := []struct {
		name        string
		env         map[string]string
		wantErrPart string
	}{
		{
			name:        "unparseable size",
			env:         map[string]string{envPrefix + "MAX_MESSAGE_BYTES": "16MB"},
			wantErrPart: "MAX_MESSAGE_BYTES",
		},
		{
			name:        "unparseable startup timeout",
			env:         map[string]string{envPrefix + "STARTUP_TIMEOUT": "ten seconds"},
			wantErrPart: "STARTUP_TIMEOUT",
		},
		{
			name:        "unparseable shutdown timeout",
			env:         map[string]string{envPrefix + "SHUTDOWN_TIMEOUT": "soon"},
			wantErrPart: "SHUTDOWN_TIMEOUT",
		},
		{
			name:        "unknown log level",
			env:         map[string]string{envPrefix + "LOG_LEVEL": "chatty"},
			wantErrPart: "LOG_LEVEL",
		},
		{
			name:        "zero size fails validation",
			env:         map[string]string{envPrefix + "MAX_MESSAGE_BYTES": "0"},
			wantErrPart: "must be positive",
		},
		{
			name:        "negative size fails validation",
			env:         map[string]string{envPrefix + "MAX_MESSAGE_BYTES": "-1"},
			wantErrPart: "must be positive",
		},
		{
			name:        "zero startup timeout fails validation",
			env:         map[string]string{envPrefix + "STARTUP_TIMEOUT": "0s"},
			wantErrPart: "must be positive",
		},
		{
			name:        "negative shutdown timeout fails validation",
			env:         map[string]string{envPrefix + "SHUTDOWN_TIMEOUT": "-5s"},
			wantErrPart: "must be positive",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Load(env(tc.env))
			if err == nil {
				t.Fatalf("Load() = %+v, want an error", got)
			}
			if !strings.Contains(err.Error(), tc.wantErrPart) {
				t.Errorf("Load() error = %q, want it to mention %q", err, tc.wantErrPart)
			}
			if got != (Config{}) {
				t.Errorf("Load() = %+v on error, want the zero Config", got)
			}
		})
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name        string
		mutate      func(*Config)
		wantErrPart string
	}{
		{
			name:   "defaults are valid",
			mutate: func(*Config) {},
		},
		{
			name:        "empty listen address",
			mutate:      func(c *Config) { c.ListenAddr = "" },
			wantErrPart: "LISTEN_ADDR",
		},
		{
			name:        "empty database url",
			mutate:      func(c *Config) { c.DatabaseURL = "" },
			wantErrPart: "DATABASE_URL",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Default()
			tc.mutate(&cfg)

			err := cfg.Validate()
			if tc.wantErrPart == "" {
				if err != nil {
					t.Fatalf("Validate() unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Validate() = nil, want an error mentioning %q", tc.wantErrPart)
			}
			if !strings.Contains(err.Error(), tc.wantErrPart) {
				t.Errorf("Validate() error = %q, want it to mention %q", err, tc.wantErrPart)
			}
		})
	}
}
