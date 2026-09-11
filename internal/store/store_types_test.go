package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"
)

func TestLeasePredicates(t *testing.T) {
	now := time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)
	hour := time.Hour

	tests := []struct {
		name        string
		lease       Lease
		wantRevoked bool
		wantExpired bool
		wantActive  bool
	}{
		{
			name:       "no expiry, not revoked",
			lease:      Lease{},
			wantActive: true,
		},
		{
			name:        "revoked",
			lease:       Lease{RevokedAt: now.Add(-hour)},
			wantRevoked: true,
		},
		{
			name:        "expired an hour ago",
			lease:       Lease{ExpiresAt: now.Add(-hour)},
			wantExpired: true,
		},
		{
			name:       "expires in an hour",
			lease:      Lease{ExpiresAt: now.Add(hour)},
			wantActive: true,
		},
		{
			name:        "expires exactly now counts as expired",
			lease:       Lease{ExpiresAt: now},
			wantExpired: true,
		},
		{
			name:        "revoked and expired",
			lease:       Lease{RevokedAt: now.Add(-hour), ExpiresAt: now.Add(-hour)},
			wantRevoked: true,
			wantExpired: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.lease.Revoked(); got != tc.wantRevoked {
				t.Errorf("Revoked() = %v, want %v", got, tc.wantRevoked)
			}
			if got := tc.lease.Expired(now); got != tc.wantExpired {
				t.Errorf("Expired() = %v, want %v", got, tc.wantExpired)
			}
			if got := tc.lease.Active(now); got != tc.wantActive {
				t.Errorf("Active() = %v, want %v", got, tc.wantActive)
			}
		})
	}
}

func TestNewLeaseValidate(t *testing.T) {
	valid := NewLease{
		TenantID:        "11111111-1111-4111-8111-111111111111",
		Key:             "lease_abc123",
		BackendHost:     "127.0.0.1",
		BackendPort:     5432,
		BackendDatabase: "tenant_db",
	}

	tests := []struct {
		name        string
		mutate      func(*NewLease)
		wantErrPart string
	}{
		{name: "valid", mutate: func(*NewLease) {}},
		{name: "zero port is allowed", mutate: func(n *NewLease) { n.BackendPort = 0 }},
		{
			name:        "empty tenant id",
			mutate:      func(n *NewLease) { n.TenantID = "" },
			wantErrPart: "tenant id",
		},
		{
			name:        "empty key",
			mutate:      func(n *NewLease) { n.Key = "" },
			wantErrPart: "key",
		},
		{
			name:        "key with a dot",
			mutate:      func(n *NewLease) { n.Key = "lease.abc" },
			wantErrPart: "key",
		},
		{
			name:        "key with a space",
			mutate:      func(n *NewLease) { n.Key = "lease abc" },
			wantErrPart: "key",
		},
		{
			name:        "key over 63 bytes",
			mutate:      func(n *NewLease) { n.Key = strings.Repeat("a", 64) },
			wantErrPart: "key",
		},
		{
			name:   "key at exactly 63 bytes",
			mutate: func(n *NewLease) { n.Key = strings.Repeat("a", 63) },
		},
		{
			name:        "empty backend host",
			mutate:      func(n *NewLease) { n.BackendHost = "" },
			wantErrPart: "backend host",
		},
		{
			name:        "empty backend database",
			mutate:      func(n *NewLease) { n.BackendDatabase = "" },
			wantErrPart: "backend database",
		},
		{
			name:        "negative port",
			mutate:      func(n *NewLease) { n.BackendPort = -1 },
			wantErrPart: "port",
		},
		{
			name:        "port above 65535",
			mutate:      func(n *NewLease) { n.BackendPort = 65536 },
			wantErrPart: "port",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			in := valid
			tc.mutate(&in)

			err := in.Validate()
			if tc.wantErrPart == "" {
				if err != nil {
					t.Fatalf("Validate() unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Validate() = nil, want an error mentioning %q", tc.wantErrPart)
			}
			if !errors.Is(err, ErrInvalidLease) {
				t.Errorf("Validate() error = %v, want it to wrap ErrInvalidLease", err)
			}
			if !strings.Contains(err.Error(), tc.wantErrPart) {
				t.Errorf("Validate() error = %q, want it to mention %q", err, tc.wantErrPart)
			}
		})
	}
}

func TestNewLeasePort(t *testing.T) {
	if got := (NewLease{BackendPort: 0}).Port(); got != DefaultBackendPort {
		t.Errorf("Port() = %d, want the default %d", got, DefaultBackendPort)
	}
	if got := (NewLease{BackendPort: 6000}).Port(); got != 6000 {
		t.Errorf("Port() = %d, want 6000", got)
	}
}

func TestTokenRedacts(t *testing.T) {
	const secret = "s3cr3t-do-not-log-me"
	tok := Token(secret)

	// Table-driving the verbs is necessary, not just tidy: a constant
	// fmt.Sprintf("%s", tok) on a Stringer trips staticcheck S1025, which is
	// in golangci-lint's default set and would fail make lint. A non-constant
	// format string is not analysed.
	for _, verb := range []string{"%v", "%s", "%q", "%x", "%+v"} {
		if got := fmt.Sprintf(verb, tok); strings.Contains(got, secret) {
			t.Errorf("%s leaked the token: %s", verb, got)
		}
	}
	if got := fmt.Sprint(tok); strings.Contains(got, secret) {
		t.Errorf("Sprint leaked the token: %s", got)
	}
	if got := fmt.Sprintf("%+v", struct{ T Token }{tok}); strings.Contains(got, secret) {
		t.Errorf("struct rendering leaked the token: %s", got)
	}
	if got := tok.String(); strings.Contains(got, secret) {
		t.Errorf("String() leaked the token: %s", got)
	}

	var buf strings.Builder
	slog.New(slog.NewTextHandler(&buf, nil)).Info("m", "token", tok)
	if strings.Contains(buf.String(), secret) {
		t.Errorf("slog leaked the token: %s", buf.String())
	}

	// %#v is governed by fmt.GoStringer, not Stringer, so String does not
	// cover it: this was the finding. GoString closes the gap.
	if got := fmt.Sprintf("%#v", tok); strings.Contains(got, secret) {
		t.Errorf("%%#v leaked the token: %s", got)
	}
	if got := fmt.Sprintf("%#v", struct{ T Token }{tok}); strings.Contains(got, secret) {
		t.Errorf("%%#v on a struct leaked the token: %s", got)
	}

	// encoding/json uses encoding.TextMarshaler, not Stringer, so String does
	// not cover it either: MarshalText closes the gap.
	b, err := json.Marshal(tok)
	if err != nil {
		t.Fatalf("json.Marshal() unexpected error: %v", err)
	}
	if strings.Contains(string(b), secret) {
		t.Errorf("json.Marshal leaked the token: %s", b)
	}

	if string(tok) != secret {
		t.Errorf("string(tok) = %q, want the real value back", string(tok))
	}
}
