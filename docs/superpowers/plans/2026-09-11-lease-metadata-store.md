# Lease Metadata Store Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give pg-lease-rate a durable tenants-and-leases schema plus a Go package that authenticates a lease key and token and reports which backend database it points at.

**Architecture:** One goose migration creates `tenants` and `leases`. `internal/store` exposes two narrow interfaces — `LeaseAuthenticator` (one method, all the gateway will need) and `Admin` (for tests and a future CLI) — with a pgx-backed implementation and an in-memory implementation. A single conformance suite runs against both, so the fake cannot drift. Lease tokens are 256-bit random values stored as SHA-256 hashes and compared in constant time; the hash never leaves the package.

**Tech Stack:** Go 1.27.1, PostgreSQL 17, `github.com/pressly/goose/v3` v3.28.0 (migrations), `github.com/jackc/pgx/v5` v5.11.0 (driver). Everything else is standard library.

**Spec:** `docs/superpowers/specs/2026-09-11-lease-metadata-store-design.md`

## Global Constraints

- Never use a TODO comment, a stub, or a placeholder implementation. Every function does what its doc comment says.
- Identifiers are `MixedCaps`/`mixedCaps`, never `snake_case`. Constants are `MixedCaps`, not `SCREAMING_SNAKE`.
- Sentinel errors are package-level `var`s with lowercase package-prefixed messages, wrapped at call sites with `%w`.
- `make test` must stay hermetic: no Docker, no network. Anything needing Postgres goes behind `//go:build integration`.
- `make all` (`fmt-check`, `vet`, `test`, `build`) and `make lint` must pass before every commit.
- The gateway binary must never link goose. Only `cmd/pglr-migrate` may import it.
- `internal/config` must not gain any external dependency; it treats the DSN as an opaque string.
- Do not modify `internal/gateway/` or `internal/pgwire/`. That is step 2's work.
- Commits are signed automatically (`commit.gpgsign=true`, ssh format). Do not pass `-S` or `--no-gpg-sign`.
- Never push. The branch is `feature/lease-store`.

---

### Task 1: Types, sentinel errors, and validation

**Files:**
- Create: `internal/store/store.go`
- Test: `internal/store/store_types_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces: `Token`, `Tenant`, `Lease`, `NewLease`, `LeaseAuthenticator`, `Admin`, `DefaultBackendPort`, and the eight sentinel errors. `Lease.Revoked() bool`, `Lease.Expired(now time.Time) bool`, `Lease.Active(now time.Time) bool`, `NewLease.Validate() error`, `NewLease.Port() int`.

- [ ] **Step 1: Write the failing test**

Create `internal/store/store_types_test.go`:

```go
package store

import (
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

	if string(tok) != secret {
		t.Errorf("string(tok) = %q, want the real value back", string(tok))
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd internal/store && go test ./... 2>&1 | head -5`

Expected: FAIL to build, with `undefined: Lease`, `undefined: NewLease`, `undefined: Token`, etc. The package does not exist yet, so `go test ./...` from the repo root also works.

- [ ] **Step 3: Write the implementation**

Create `internal/store/store.go`:

```go
// Package store persists the gateway's lease metadata: which tenants exist,
// which leases they own, and which backend database each lease points at.
//
// A client presents a lease key as the "database" startup parameter and a
// lease token as its password. Authenticate turns that pair into a Lease. The
// stored token hash never leaves this package, so no caller can compare one
// incorrectly.
//
// Two interfaces divide the surface by consumer. LeaseAuthenticator is the
// single method the gateway needs. Admin is everything else, for tests and
// operator tooling; the gateway must not depend on it.
package store

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"time"
)

// Conditions this package reports. Callers match them with errors.Is.
var (
	// ErrLeaseNotFound reports a lease key with no row.
	ErrLeaseNotFound = errors.New("store: lease not found")
	// ErrTokenMismatch reports a token that does not hash to the stored value.
	ErrTokenMismatch = errors.New("store: lease token does not match")
	// ErrLeaseRevoked reports a lease whose revoked_at is set.
	ErrLeaseRevoked = errors.New("store: lease revoked")
	// ErrLeaseExpired reports a lease past its expires_at.
	ErrLeaseExpired = errors.New("store: lease expired")
	// ErrTenantNotFound reports a tenant id with no row.
	ErrTenantNotFound = errors.New("store: tenant not found")
	// ErrAlreadyExists reports a duplicate tenant name or lease key.
	ErrAlreadyExists = errors.New("store: already exists")
	// ErrInvalidLease reports a NewLease that fails validation.
	ErrInvalidLease = errors.New("store: invalid lease")
	// ErrSchemaVersion reports a database whose applied migration version is
	// not the one this build expects.
	ErrSchemaVersion = errors.New("store: unexpected schema version")
)

// DefaultBackendPort is the port used when a NewLease leaves BackendPort zero.
const DefaultBackendPort = 5432

// leaseKeyPattern bounds a value that arrives from an untrusted startup
// parameter and reaches the logs. 63 bytes is PostgreSQL's identifier limit.
var leaseKeyPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,63}$`)

// Token is a lease's plaintext secret. It is returned exactly once, when the
// lease is created, and is never stored: only its hash is.
//
// Token is a defined type rather than a string so that transposing the
// arguments of Authenticate is a compile error rather than an authentication
// bug, and so that String and LogValue can keep it out of logs.
type Token string

// String redacts. Call string(t) to obtain the real value.
//
// This covers every fmt verb that go vet accepts. A numeric verb such as %d
// embeds the value in fmt's bad-verb message, but vet rejects that at build
// time and make all runs vet.
func (t Token) String() string { return "[REDACTED]" }

// LogValue redacts in slog output.
func (t Token) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

// Tenant owns leases.
type Tenant struct {
	ID        string
	Name      string
	CreatedAt time.Time
}

// Lease maps a lease key to a backend database. It carries no token hash by
// design; see Authenticate.
type Lease struct {
	ID       string
	TenantID string

	// Key is the value a client sends as the "database" startup parameter.
	Key string

	// BackendHost, BackendPort and BackendDatabase name the database this
	// lease grants access to. Credentials come from gateway configuration, so
	// that no secret is stored here.
	BackendHost     string
	BackendPort     int
	BackendDatabase string

	// ExpiresAt is when the lease stops working. Zero means it never expires.
	ExpiresAt time.Time

	// RevokedAt is when the lease was revoked. Zero means it is not revoked.
	RevokedAt time.Time

	CreatedAt time.Time
}

// Revoked reports whether the lease has been revoked.
func (l Lease) Revoked() bool { return !l.RevokedAt.IsZero() }

// Expired reports whether the lease has expired as of now. A lease whose
// expiry is exactly now counts as expired.
//
// now is a parameter rather than a call to time.Now so that this is testable
// without injecting a clock.
func (l Lease) Expired(now time.Time) bool {
	return !l.ExpiresAt.IsZero() && !now.Before(l.ExpiresAt)
}

// Active reports whether the lease is neither revoked nor expired.
func (l Lease) Active(now time.Time) bool { return !l.Revoked() && !l.Expired(now) }

// NewLease describes a lease to create.
type NewLease struct {
	TenantID        string
	Key             string
	BackendHost     string
	BackendPort     int // zero selects DefaultBackendPort
	BackendDatabase string
	ExpiresAt       time.Time // zero means no expiry
}

// Validate reports whether n can be stored. The schema carries equivalent
// CHECK constraints as a backstop, so a constraint violation coming back from
// PostgreSQL means this function has drifted from the schema.
func (n NewLease) Validate() error {
	if n.TenantID == "" {
		return fmt.Errorf("%w: tenant id is empty", ErrInvalidLease)
	}
	if !leaseKeyPattern.MatchString(n.Key) {
		return fmt.Errorf("%w: key %q must match %s", ErrInvalidLease, n.Key, leaseKeyPattern)
	}
	if n.BackendHost == "" {
		return fmt.Errorf("%w: backend host is empty", ErrInvalidLease)
	}
	if n.BackendDatabase == "" {
		return fmt.Errorf("%w: backend database is empty", ErrInvalidLease)
	}
	if n.BackendPort < 0 || n.BackendPort > 65535 {
		return fmt.Errorf("%w: backend port %d is out of range", ErrInvalidLease, n.BackendPort)
	}
	return nil
}

// Port returns the backend port, substituting DefaultBackendPort for zero.
func (n NewLease) Port() int {
	if n.BackendPort == 0 {
		return DefaultBackendPort
	}
	return n.BackendPort
}

// LeaseAuthenticator resolves a lease key and token to a Lease. It is the only
// part of this package the gateway depends on.
type LeaseAuthenticator interface {
	// Authenticate returns the lease named by leaseKey if token matches it and
	// the lease is active.
	//
	// It reports, in this order: ErrLeaseNotFound for an unknown key,
	// ErrTokenMismatch for a bad token, then ErrLeaseRevoked or
	// ErrLeaseExpired. Verifying the token first means revocation and expiry
	// are only ever disclosed to a caller that already holds the token.
	//
	// Callers that speak to clients must collapse ErrLeaseNotFound and
	// ErrTokenMismatch into one client-facing error; distinguishing them is a
	// lease-key enumeration oracle.
	Authenticate(ctx context.Context, leaseKey string, token Token) (Lease, error)
}

// Admin creates and inspects metadata. It is for tests and operator tooling;
// the gateway must not depend on it.
type Admin interface {
	// CreateTenant returns ErrAlreadyExists if the name is taken, compared
	// case-insensitively.
	CreateTenant(ctx context.Context, name string) (Tenant, error)

	// CreateLease validates in, generates a token, stores the token's hash,
	// and returns the plaintext token exactly once. There is no way to read it
	// back.
	//
	// It reports ErrInvalidLease for a bad field, ErrTenantNotFound for an
	// unknown TenantID, and ErrAlreadyExists for a duplicate key.
	CreateLease(ctx context.Context, in NewLease) (Lease, Token, error)

	// Lease reads a lease without authenticating it. Unlike Authenticate it
	// returns revoked and expired leases as ordinary results, with RevokedAt
	// and ExpiresAt set, so an operator can inspect them. Only an absent row
	// is ErrLeaseNotFound.
	Lease(ctx context.Context, leaseKey string) (Lease, error)

	// RevokeLease sets revoked_at. It is idempotent: revoking an
	// already-revoked lease succeeds and leaves the original timestamp
	// unchanged. An unknown key is ErrLeaseNotFound.
	RevokeLease(ctx context.Context, leaseKey string) error
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/store/ -v 2>&1 | tail -20`

Expected: PASS. `TestTokenRedacts` will fail to compile until Task 2 if you wrote `%x` expecting `hashToken`; it does not — it only formats the `Token`, so it passes now.

- [ ] **Step 5: Verify and commit**

```bash
gofmt -l . && go vet ./... && golangci-lint run && go test -race ./...
git add internal/store/store.go internal/store/store_types_test.go
git commit -m "Add lease and tenant types with validation

Introduces internal/store with the Tenant, Lease and NewLease types, the two
consumer-split interfaces, and the package's sentinel errors. Lease status is
derived from the revoked_at and expires_at timestamps rather than stored, so
the two cannot disagree.

Token is a defined string type whose String and LogValue methods redact, which
keeps a lease secret out of logs and makes transposing Authenticate's
arguments a compile error."
```

---

### Task 2: Token generation, hashing, and verification

**Files:**
- Create: `internal/store/token.go`
- Test: `internal/store/token_test.go`

**Interfaces:**
- Consumes: `Token` from Task 1.
- Produces: `NewToken() Token`, and package-private `hashToken(Token) []byte`, `verifyToken(Token, []byte) bool`, `dummyHash []byte`, `tokenBytes`, `tokenHashBytes`.

- [ ] **Step 1: Write the failing test**

Create `internal/store/token_test.go`:

```go
package store

import (
	"bytes"
	"testing"
)

func TestNewTokenShape(t *testing.T) {
	const want = 43 // base64url of 32 bytes, unpadded

	seen := make(map[Token]bool, 100)
	for range 100 {
		tok := NewToken()
		if len(tok) != want {
			t.Fatalf("NewToken() length = %d, want %d", len(tok), want)
		}
		if seen[tok] {
			t.Fatalf("NewToken() returned a duplicate: %s", string(tok))
		}
		seen[tok] = true
	}
}

func TestHashToken(t *testing.T) {
	tok := NewToken()

	first := hashToken(tok)
	if len(first) != tokenHashBytes {
		t.Fatalf("hashToken() length = %d, want %d", len(first), tokenHashBytes)
	}
	if !bytes.Equal(first, hashToken(tok)) {
		t.Error("hashToken() is not deterministic")
	}
	if bytes.Equal(first, hashToken(NewToken())) {
		t.Error("hashToken() collided across two different tokens")
	}
	if bytes.Contains(first, []byte(tok)) {
		t.Error("the hash contains the plaintext token")
	}
}

func TestVerifyToken(t *testing.T) {
	tok := NewToken()
	other := NewToken()
	want := hashToken(tok)

	tests := []struct {
		name    string
		present Token
		against []byte
		want    bool
	}{
		{name: "correct token", present: tok, against: want, want: true},
		{name: "different token", present: other, against: want},
		{name: "empty token", present: "", against: want},
		{name: "against the dummy hash", present: tok, against: dummyHash},
		{name: "against a wrong-length hash", present: tok, against: want[:16]},
		{name: "against a nil hash", present: tok, against: nil},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := verifyToken(tc.present, tc.against); got != tc.want {
				t.Errorf("verifyToken() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestDummyHashIsUnmatchable(t *testing.T) {
	if len(dummyHash) != tokenHashBytes {
		t.Fatalf("dummyHash length = %d, want %d", len(dummyHash), tokenHashBytes)
	}
	// A fresh random token must not verify against it. This is a sanity check
	// on the not-found path of Authenticate, which compares against dummyHash
	// so that its cost does not depend on whether the lease exists.
	for range 100 {
		if verifyToken(NewToken(), dummyHash) {
			t.Fatal("a token verified against dummyHash")
		}
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/store/ -run 'Token|Dummy' 2>&1 | head -5`

Expected: FAIL to build with `undefined: NewToken`, `undefined: hashToken`, `undefined: verifyToken`, `undefined: dummyHash`, `undefined: tokenHashBytes`.

- [ ] **Step 3: Write the implementation**

Create `internal/store/token.go`:

```go
package store

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
)

// tokenBytes is the entropy of a generated lease token. 256 bits is why the
// stored form is a plain SHA-256 and not a password-hashing function: a KDF
// exists to make guessing expensive, and there is nothing here to guess. A KDF
// would instead add tens of milliseconds to every client connection.
const tokenBytes = 32

// tokenHashBytes is the width of a SHA-256 digest. The schema enforces it.
const tokenHashBytes = sha256.Size

// dummyHash is what Authenticate compares against when a lease key has no
// row, so that the comparison's cost does not depend on whether the lease
// exists. It is the hash of a random token generated at startup, so nothing
// can verify against it.
var dummyHash = hashToken(NewToken())

// NewToken returns a fresh random lease token.
//
// crypto/rand.Read is documented never to return an error: it crashes the
// process irrecoverably if the operating system's entropy source fails. So
// this cannot fail and returns no error.
func NewToken() Token {
	b := make([]byte, tokenBytes)
	_, _ = rand.Read(b)
	return Token(base64.RawURLEncoding.EncodeToString(b))
}

// hashToken returns the SHA-256 of t. This is the only form of a token that is
// ever stored.
func hashToken(t Token) []byte {
	sum := sha256.Sum256([]byte(t))
	return sum[:]
}

// verifyToken reports whether t hashes to want, comparing in constant time.
// A want of the wrong length never matches.
func verifyToken(t Token, want []byte) bool {
	return subtle.ConstantTimeCompare(hashToken(t), want) == 1
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/store/ -race -v -run 'Token|Dummy' 2>&1 | tail -25`

Expected: PASS, including `TestTokenRedacts` from Task 1.

- [ ] **Step 5: Verify and commit**

```bash
gofmt -l . && go vet ./... && golangci-lint run && go test -race ./...
git add internal/store/token.go internal/store/token_test.go
git commit -m "Add lease token generation, hashing and verification

Lease tokens are 32 random bytes, base64url-encoded to 43 characters, stored
only as a SHA-256 digest and compared with crypto/subtle.ConstantTimeCompare.

A plain digest rather than bcrypt or argon2 is deliberate: a password-hashing
function exists to make guessing expensive, and 256 bits of entropy leaves
nothing to guess, while a KDF would add tens of milliseconds to every client
connection. For the same reason no salt is needed.

dummyHash gives Authenticate something constant-time to compare against when a
lease key has no row, so its cost does not reveal whether the lease exists."
```

---

### Task 3: Conformance suite and the in-memory store

**Files:**
- Create: `internal/store/memory.go`
- Create: `internal/store/store_test.go` (the conformance suite, no build tag)
- Create: `internal/store/memory_test.go`

**Interfaces:**
- Consumes: everything from Tasks 1 and 2.
- Produces: `NewMemory() *Memory` satisfying both `LeaseAuthenticator` and `Admin`; the test helpers `testStore` and `runConformance(t *testing.T, newStore func(*testing.T) testStore)` used again by Task 5.

- [ ] **Step 1: Write the failing conformance suite**

Create `internal/store/store_test.go`. This file carries **no build tag**, so it compiles into both the hermetic and the integration test binaries.

```go
package store

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// testStore is the full surface the conformance suite exercises. It is
// unexported so the package's public API stays two narrow interfaces.
type testStore interface {
	LeaseAuthenticator
	Admin
}

// newLeaseFor builds a valid NewLease for a tenant.
func newLeaseFor(tenantID, key string) NewLease {
	return NewLease{
		TenantID:        tenantID,
		Key:             key,
		BackendHost:     "127.0.0.1",
		BackendPort:     5432,
		BackendDatabase: "tenant_db",
	}
}

// runConformance is the contract every Store implementation must satisfy. It
// is run against *Memory on every build and against *Postgres under the
// integration tag, so the two cannot drift.
func runConformance(t *testing.T, newStore func(*testing.T) testStore) {
	t.Helper()
	ctx := context.Background()

	t.Run("authenticate with the created token", func(t *testing.T) {
		s := newStore(t)
		tenant, err := s.CreateTenant(ctx, "acme")
		if err != nil {
			t.Fatalf("CreateTenant() unexpected error: %v", err)
		}
		created, token, err := s.CreateLease(ctx, newLeaseFor(tenant.ID, "lease_abc123"))
		if err != nil {
			t.Fatalf("CreateLease() unexpected error: %v", err)
		}

		got, err := s.Authenticate(ctx, "lease_abc123", token)
		if err != nil {
			t.Fatalf("Authenticate() unexpected error: %v", err)
		}
		if got.ID != created.ID {
			t.Errorf("ID = %q, want %q", got.ID, created.ID)
		}
		if got.Key != "lease_abc123" {
			t.Errorf("Key = %q, want %q", got.Key, "lease_abc123")
		}
		if got.TenantID != tenant.ID {
			t.Errorf("TenantID = %q, want %q", got.TenantID, tenant.ID)
		}
		if got.BackendDatabase != "tenant_db" {
			t.Errorf("BackendDatabase = %q, want %q", got.BackendDatabase, "tenant_db")
		}
		if got.BackendPort != 5432 {
			t.Errorf("BackendPort = %d, want 5432", got.BackendPort)
		}
		if !got.Active(time.Now()) {
			t.Error("Active() = false, want a freshly created lease to be active")
		}
	})

	t.Run("unknown lease key", func(t *testing.T) {
		s := newStore(t)
		if _, err := s.Authenticate(ctx, "no_such_lease", NewToken()); !errors.Is(err, ErrLeaseNotFound) {
			t.Errorf("Authenticate() error = %v, want ErrLeaseNotFound", err)
		}
	})

	t.Run("wrong token", func(t *testing.T) {
		s := newStore(t)
		tenant, _ := s.CreateTenant(ctx, "acme")
		if _, _, err := s.CreateLease(ctx, newLeaseFor(tenant.ID, "lease_abc123")); err != nil {
			t.Fatalf("CreateLease() unexpected error: %v", err)
		}
		if _, err := s.Authenticate(ctx, "lease_abc123", NewToken()); !errors.Is(err, ErrTokenMismatch) {
			t.Errorf("Authenticate() error = %v, want ErrTokenMismatch", err)
		}
	})

	t.Run("revoked lease with the correct token", func(t *testing.T) {
		s := newStore(t)
		tenant, _ := s.CreateTenant(ctx, "acme")
		_, token, _ := s.CreateLease(ctx, newLeaseFor(tenant.ID, "lease_abc123"))
		if err := s.RevokeLease(ctx, "lease_abc123"); err != nil {
			t.Fatalf("RevokeLease() unexpected error: %v", err)
		}
		if _, err := s.Authenticate(ctx, "lease_abc123", token); !errors.Is(err, ErrLeaseRevoked) {
			t.Errorf("Authenticate() error = %v, want ErrLeaseRevoked", err)
		}
	})

	// This is the regression test for the ordering decision: the token is
	// verified BEFORE revocation is checked, so a bad token on a revoked lease
	// must report the token problem and disclose nothing about the lease.
	t.Run("revoked lease with a wrong token reports the token", func(t *testing.T) {
		s := newStore(t)
		tenant, _ := s.CreateTenant(ctx, "acme")
		if _, _, err := s.CreateLease(ctx, newLeaseFor(tenant.ID, "lease_abc123")); err != nil {
			t.Fatalf("CreateLease() unexpected error: %v", err)
		}
		if err := s.RevokeLease(ctx, "lease_abc123"); err != nil {
			t.Fatalf("RevokeLease() unexpected error: %v", err)
		}
		_, err := s.Authenticate(ctx, "lease_abc123", NewToken())
		if !errors.Is(err, ErrTokenMismatch) {
			t.Errorf("Authenticate() error = %v, want ErrTokenMismatch", err)
		}
		if errors.Is(err, ErrLeaseRevoked) {
			t.Error("Authenticate() disclosed revocation to a caller with a bad token")
		}
	})

	t.Run("expired lease with the correct token", func(t *testing.T) {
		s := newStore(t)
		tenant, _ := s.CreateTenant(ctx, "acme")
		in := newLeaseFor(tenant.ID, "lease_abc123")
		in.ExpiresAt = time.Now().Add(-time.Hour)
		_, token, err := s.CreateLease(ctx, in)
		if err != nil {
			t.Fatalf("CreateLease() unexpected error: %v", err)
		}
		if _, err := s.Authenticate(ctx, "lease_abc123", token); !errors.Is(err, ErrLeaseExpired) {
			t.Errorf("Authenticate() error = %v, want ErrLeaseExpired", err)
		}
	})

	t.Run("future expiry still authenticates", func(t *testing.T) {
		s := newStore(t)
		tenant, _ := s.CreateTenant(ctx, "acme")
		in := newLeaseFor(tenant.ID, "lease_abc123")
		in.ExpiresAt = time.Now().Add(time.Hour)
		_, token, err := s.CreateLease(ctx, in)
		if err != nil {
			t.Fatalf("CreateLease() unexpected error: %v", err)
		}
		if _, err := s.Authenticate(ctx, "lease_abc123", token); err != nil {
			t.Errorf("Authenticate() unexpected error: %v", err)
		}
	})

	t.Run("duplicate lease key", func(t *testing.T) {
		s := newStore(t)
		tenant, _ := s.CreateTenant(ctx, "acme")
		if _, _, err := s.CreateLease(ctx, newLeaseFor(tenant.ID, "lease_abc123")); err != nil {
			t.Fatalf("first CreateLease() unexpected error: %v", err)
		}
		if _, _, err := s.CreateLease(ctx, newLeaseFor(tenant.ID, "lease_abc123")); !errors.Is(err, ErrAlreadyExists) {
			t.Errorf("second CreateLease() error = %v, want ErrAlreadyExists", err)
		}
	})

	t.Run("duplicate tenant name differing only in case", func(t *testing.T) {
		s := newStore(t)
		if _, err := s.CreateTenant(ctx, "Acme"); err != nil {
			t.Fatalf("first CreateTenant() unexpected error: %v", err)
		}
		if _, err := s.CreateTenant(ctx, "aCMe"); !errors.Is(err, ErrAlreadyExists) {
			t.Errorf("second CreateTenant() error = %v, want ErrAlreadyExists", err)
		}
	})

	t.Run("lease under an unknown tenant", func(t *testing.T) {
		s := newStore(t)
		in := newLeaseFor("11111111-1111-4111-8111-111111111111", "lease_abc123")
		if _, _, err := s.CreateLease(ctx, in); !errors.Is(err, ErrTenantNotFound) {
			t.Errorf("CreateLease() error = %v, want ErrTenantNotFound", err)
		}
	})

	t.Run("invalid lease is rejected before any write", func(t *testing.T) {
		s := newStore(t)
		tenant, _ := s.CreateTenant(ctx, "acme")

		bad := map[string]func(*NewLease){
			"key with a dot":   func(n *NewLease) { n.Key = "lease.abc" },
			"empty key":        func(n *NewLease) { n.Key = "" },
			"key over 63":      func(n *NewLease) { n.Key = strings.Repeat("a", 64) },
			"port too high":    func(n *NewLease) { n.BackendPort = 70000 },
			"negative port":    func(n *NewLease) { n.BackendPort = -1 },
			"empty host":       func(n *NewLease) { n.BackendHost = "" },
			"empty database":   func(n *NewLease) { n.BackendDatabase = "" },
		}
		for name, mutate := range bad {
			t.Run(name, func(t *testing.T) {
				in := newLeaseFor(tenant.ID, "lease_ok")
				mutate(&in)
				if _, _, err := s.CreateLease(ctx, in); !errors.Is(err, ErrInvalidLease) {
					t.Errorf("CreateLease() error = %v, want ErrInvalidLease", err)
				}
			})
		}
	})

	t.Run("zero backend port defaults to 5432", func(t *testing.T) {
		s := newStore(t)
		tenant, _ := s.CreateTenant(ctx, "acme")
		in := newLeaseFor(tenant.ID, "lease_abc123")
		in.BackendPort = 0
		created, _, err := s.CreateLease(ctx, in)
		if err != nil {
			t.Fatalf("CreateLease() unexpected error: %v", err)
		}
		if created.BackendPort != DefaultBackendPort {
			t.Errorf("BackendPort = %d, want %d", created.BackendPort, DefaultBackendPort)
		}
	})

	t.Run("two leases get different tokens", func(t *testing.T) {
		s := newStore(t)
		tenant, _ := s.CreateTenant(ctx, "acme")
		_, first, _ := s.CreateLease(ctx, newLeaseFor(tenant.ID, "lease_one"))
		_, second, _ := s.CreateLease(ctx, newLeaseFor(tenant.ID, "lease_two"))
		if first == second {
			t.Error("two leases were issued the same token")
		}
		if _, err := s.Authenticate(ctx, "lease_one", second); !errors.Is(err, ErrTokenMismatch) {
			t.Errorf("Authenticate() with the other lease's token error = %v, want ErrTokenMismatch", err)
		}
	})

	t.Run("Lease returns a revoked lease", func(t *testing.T) {
		s := newStore(t)
		tenant, _ := s.CreateTenant(ctx, "acme")
		if _, _, err := s.CreateLease(ctx, newLeaseFor(tenant.ID, "lease_abc123")); err != nil {
			t.Fatalf("CreateLease() unexpected error: %v", err)
		}
		if err := s.RevokeLease(ctx, "lease_abc123"); err != nil {
			t.Fatalf("RevokeLease() unexpected error: %v", err)
		}
		got, err := s.Lease(ctx, "lease_abc123")
		if err != nil {
			t.Fatalf("Lease() unexpected error: %v", err)
		}
		if !got.Revoked() {
			t.Error("Lease() returned a lease that does not report itself revoked")
		}
	})

	t.Run("Lease on an unknown key", func(t *testing.T) {
		s := newStore(t)
		if _, err := s.Lease(ctx, "no_such_lease"); !errors.Is(err, ErrLeaseNotFound) {
			t.Errorf("Lease() error = %v, want ErrLeaseNotFound", err)
		}
	})

	t.Run("RevokeLease is idempotent", func(t *testing.T) {
		s := newStore(t)
		tenant, _ := s.CreateTenant(ctx, "acme")
		if _, _, err := s.CreateLease(ctx, newLeaseFor(tenant.ID, "lease_abc123")); err != nil {
			t.Fatalf("CreateLease() unexpected error: %v", err)
		}
		if err := s.RevokeLease(ctx, "lease_abc123"); err != nil {
			t.Fatalf("first RevokeLease() unexpected error: %v", err)
		}
		first, err := s.Lease(ctx, "lease_abc123")
		if err != nil {
			t.Fatalf("Lease() unexpected error: %v", err)
		}
		if err := s.RevokeLease(ctx, "lease_abc123"); err != nil {
			t.Fatalf("second RevokeLease() error = %v, want nil", err)
		}
		second, err := s.Lease(ctx, "lease_abc123")
		if err != nil {
			t.Fatalf("Lease() unexpected error: %v", err)
		}
		if !second.RevokedAt.Equal(first.RevokedAt) {
			t.Errorf("RevokedAt changed on the second revoke: %v then %v", first.RevokedAt, second.RevokedAt)
		}
	})

	t.Run("RevokeLease on an unknown key", func(t *testing.T) {
		s := newStore(t)
		if err := s.RevokeLease(ctx, "no_such_lease"); !errors.Is(err, ErrLeaseNotFound) {
			t.Errorf("RevokeLease() error = %v, want ErrLeaseNotFound", err)
		}
	})
}
```

- [ ] **Step 2: Add the memory runner and run it to verify it fails**

Create `internal/store/memory_test.go`:

```go
package store

import "testing"

func TestMemoryConformance(t *testing.T) {
	runConformance(t, func(t *testing.T) testStore {
		t.Helper()
		return NewMemory()
	})
}
```

Run: `go test ./internal/store/ -run Conformance 2>&1 | head -5`

Expected: FAIL to build with `undefined: NewMemory`.

- [ ] **Step 3: Write the implementation**

Create `internal/store/memory.go`:

```go
package store

import (
	"context"
	"crypto/rand"
	"fmt"
	"strings"
	"sync"
	"time"
)

// Memory is an in-memory Store. It exists so that callers can be tested
// without a database, and so that this package's hermetic tests link no
// driver. It behaves identically to *Postgres, which the shared conformance
// suite enforces.
//
// Memory is safe for concurrent use.
type Memory struct {
	mu sync.RWMutex

	tenants     map[string]Tenant // by tenant ID
	tenantNames map[string]string // lower(name) -> tenant ID
	leases      map[string]memLease
}

// memLease pairs a lease with its token hash, which Lease itself never
// carries.
type memLease struct {
	lease     Lease
	tokenHash []byte
}

// NewMemory returns an empty in-memory store.
func NewMemory() *Memory {
	return &Memory{
		tenants:     make(map[string]Tenant),
		tenantNames: make(map[string]string),
		leases:      make(map[string]memLease),
	}
}

// newID returns a random RFC 4122 version 4 UUID. PostgreSQL generates these
// itself via gen_random_uuid; this keeps the two implementations' ID shapes
// the same without taking a UUID dependency.
func newID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// CreateTenant implements Admin.
func (m *Memory) CreateTenant(_ context.Context, name string) (Tenant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := strings.ToLower(name)
	if _, ok := m.tenantNames[key]; ok {
		return Tenant{}, fmt.Errorf("%w: tenant %q", ErrAlreadyExists, name)
	}

	tenant := Tenant{ID: newID(), Name: name, CreatedAt: time.Now().UTC()}
	m.tenants[tenant.ID] = tenant
	m.tenantNames[key] = tenant.ID
	return tenant, nil
}

// CreateLease implements Admin.
func (m *Memory) CreateLease(_ context.Context, in NewLease) (Lease, Token, error) {
	if err := in.Validate(); err != nil {
		return Lease{}, "", err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.tenants[in.TenantID]; !ok {
		return Lease{}, "", fmt.Errorf("%w: %q", ErrTenantNotFound, in.TenantID)
	}
	if _, ok := m.leases[in.Key]; ok {
		return Lease{}, "", fmt.Errorf("%w: lease %q", ErrAlreadyExists, in.Key)
	}

	token := NewToken()
	lease := Lease{
		ID:              newID(),
		TenantID:        in.TenantID,
		Key:             in.Key,
		BackendHost:     in.BackendHost,
		BackendPort:     in.Port(),
		BackendDatabase: in.BackendDatabase,
		ExpiresAt:       in.ExpiresAt,
		CreatedAt:       time.Now().UTC(),
	}
	m.leases[in.Key] = memLease{lease: lease, tokenHash: hashToken(token)}
	return lease, token, nil
}

// Lease implements Admin.
func (m *Memory) Lease(_ context.Context, leaseKey string) (Lease, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	entry, ok := m.leases[leaseKey]
	if !ok {
		return Lease{}, fmt.Errorf("%w: %q", ErrLeaseNotFound, leaseKey)
	}
	return entry.lease, nil
}

// RevokeLease implements Admin.
func (m *Memory) RevokeLease(_ context.Context, leaseKey string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	entry, ok := m.leases[leaseKey]
	if !ok {
		return fmt.Errorf("%w: %q", ErrLeaseNotFound, leaseKey)
	}
	if entry.lease.Revoked() {
		return nil // idempotent: keep the original timestamp
	}
	entry.lease.RevokedAt = time.Now().UTC()
	m.leases[leaseKey] = entry
	return nil
}

// Authenticate implements LeaseAuthenticator.
func (m *Memory) Authenticate(_ context.Context, leaseKey string, token Token) (Lease, error) {
	m.mu.RLock()
	entry, ok := m.leases[leaseKey]
	m.mu.RUnlock()

	if !ok {
		// Compare against the dummy hash anyway, so this path costs what a
		// found path costs. Timing does not matter for an in-memory fake, but
		// matching *Postgres exactly is what lets one suite cover both.
		_ = verifyToken(token, dummyHash)
		return Lease{}, fmt.Errorf("%w: %q", ErrLeaseNotFound, leaseKey)
	}
	if !verifyToken(token, entry.tokenHash) {
		return Lease{}, fmt.Errorf("%w: lease %q", ErrTokenMismatch, leaseKey)
	}
	if entry.lease.Revoked() {
		return Lease{}, fmt.Errorf("%w: lease %q", ErrLeaseRevoked, leaseKey)
	}
	if entry.lease.Expired(time.Now()) {
		return Lease{}, fmt.Errorf("%w: lease %q", ErrLeaseExpired, leaseKey)
	}
	return entry.lease, nil
}

// Compile-time proof that *Memory satisfies both interfaces.
var (
	_ LeaseAuthenticator = (*Memory)(nil)
	_ Admin              = (*Memory)(nil)
)
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/store/ -race -v -run Conformance 2>&1 | tail -30`

Expected: PASS, every subtest.

- [ ] **Step 5: Verify and commit**

```bash
gofmt -l . && go vet ./... && golangci-lint run && go test -race ./...
git add internal/store/memory.go internal/store/store_test.go internal/store/memory_test.go
git commit -m "Add the store conformance suite and an in-memory implementation

store_test.go holds one suite describing the contract every implementation
must satisfy; it carries no build tag so it compiles into both the hermetic
and the integration test binary. Memory satisfies it today and Postgres will
satisfy the same suite, so the fake cannot drift from the real thing.

The suite pins the ordering decision from the design: authenticating a revoked
lease with a wrong token must report the token mismatch and not disclose the
revocation, which would pass trivially if the status checks ran first."
```

---

### Task 4: goose, the migration, and `cmd/pglr-migrate`

**Files:**
- Create: `internal/store/migrations/00001_tenants_and_leases.sql`
- Create: `internal/store/migrate.go`
- Create: `cmd/pglr-migrate/main.go`
- Modify: `Makefile` (add `migrate`, `migrate-down`, `migrate-status`; change `build`)
- Modify: `go.mod`, `go.sum`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: `store.Migrations embed.FS`, `store.MigrationsDir = "migrations"`, `store.ExpectedVersion int64 = 1`. Task 6 adds `CheckSchema` to the same file.

- [ ] **Step 1: Add the dependencies**

```bash
go get github.com/pressly/goose/v3@v3.28.0
go get github.com/jackc/pgx/v5@v5.11.0
go mod tidy
```

Expected: `go.mod` gains both as direct requirements. Confirm the gateway does not link goose:

```bash
go list -deps ./cmd/pglrd | grep -c goose
```

Expected: `0`.

- [ ] **Step 2: Write the migration**

Create `internal/store/migrations/00001_tenants_and_leases.sql`:

```sql
-- +goose Up
CREATE TABLE tenants (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name        text NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX tenants_name_key ON tenants (lower(name));

CREATE TABLE leases (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id        uuid NOT NULL REFERENCES tenants (id) ON DELETE RESTRICT,
    lease_key        text NOT NULL,
    token_hash       bytea NOT NULL,
    backend_host     text NOT NULL,
    backend_port     integer NOT NULL DEFAULT 5432,
    backend_database text NOT NULL,
    expires_at       timestamptz,
    revoked_at       timestamptz,
    created_at       timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT leases_lease_key_valid CHECK (lease_key ~ '^[A-Za-z0-9_-]{1,63}$'),
    CONSTRAINT leases_token_hash_len  CHECK (octet_length(token_hash) = 32),
    CONSTRAINT leases_backend_port_ok CHECK (backend_port BETWEEN 1 AND 65535)
);

CREATE UNIQUE INDEX leases_lease_key_key ON leases (lease_key);
CREATE INDEX leases_tenant_id_idx ON leases (tenant_id);

-- +goose Down
DROP TABLE leases;
DROP TABLE tenants;
```

- [ ] **Step 3: Write the embed and version constant**

Create `internal/store/migrate.go`:

```go
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
```

- [ ] **Step 4: Write the migrate command**

Create `cmd/pglr-migrate/main.go`:

```go
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
```

This depends on `cfg.DatabaseURL`, which Task 6 adds. To keep this task independently testable, add the config field now as part of this task — Step 5.

- [ ] **Step 5: Add `DatabaseURL` to the configuration**

In `internal/config/config.go`, add the field to `Config` after `ListenAddr`:

```go
	// DatabaseURL is the metadata database this gateway reads leases from.
	// It is kept as an opaque string so that this package takes no driver
	// dependency; internal/store parses it and reports a useful error.
	DatabaseURL string
```

Add to `Default()`:

```go
		DatabaseURL: "postgres://postgres:postgres@127.0.0.1:5432/pglr?sslmode=disable",
```

Add to `Load`, directly after the `LISTEN_ADDR` block:

```go
	if v := getenv(envPrefix + "DATABASE_URL"); v != "" {
		cfg.DatabaseURL = v
	}
```

Add to `Validate`, after the `ListenAddr` check:

```go
	if c.DatabaseURL == "" {
		return fmt.Errorf("config: %sDATABASE_URL must not be empty", envPrefix)
	}
```

In `internal/config/config_test.go`, add `envPrefix + "DATABASE_URL": "postgres://u@h:5/d"` to the "every setting overridden" case's env map and `DatabaseURL: "postgres://u@h:5/d"` to its `want`, and add this case to `TestValidate`:

```go
		{
			name:        "empty database url",
			mutate:      func(c *Config) { c.DatabaseURL = "" },
			wantErrPart: "DATABASE_URL",
		},
```

- [ ] **Step 6: Add the Makefile targets**

Change the `build` target so it builds both binaries:

```make
.PHONY: build
build:
	go build -o bin/ ./cmd/...
```

Add after the `test` target:

```make
.PHONY: migrate
migrate:
	go run ./cmd/pglr-migrate up

.PHONY: migrate-down
migrate-down:
	go run ./cmd/pglr-migrate down

.PHONY: migrate-status
migrate-status:
	go run ./cmd/pglr-migrate status
```

- [ ] **Step 7: Verify the migration applies**

```bash
make up
# wait for the healthcheck
docker compose ps
make migrate
make migrate-status
```

Expected: `migrate` reports `OK   00001_tenants_and_leases.sql`, and `migrate-status` shows it applied with a timestamp.

Confirm the schema:

```bash
docker compose exec -T postgres psql -U postgres -d pglr -c '\d leases'
docker compose exec -T postgres psql -U postgres -d pglr -c 'SELECT max(version_id) FROM goose_db_version'
```

Expected: the `leases` table with all three CHECK constraints, and version `1`.

Confirm `down` works, then re-apply:

```bash
make migrate-down && make migrate-status && make migrate
```

Expected: `down` drops both tables; status shows the migration pending; `migrate` re-applies it.

- [ ] **Step 8: Verify and commit**

```bash
gofmt -l . && go vet ./... && golangci-lint run && go test -race ./... && go build -o bin/ ./cmd/...
go list -deps ./cmd/pglrd | grep -c goose   # must print 0
git add go.mod go.sum Makefile internal/store/migrations internal/store/migrate.go cmd/pglr-migrate internal/config
git commit -m "Add the tenants and leases migration and pglr-migrate

Creates the schema with one goose migration and a command to apply it. The
leases table stores backend host, port and database rather than a DSN, so no
credential is kept in the metadata database; the gateway dials backends with
its own credentials.

Migrations are a deploy step: pglrd will only verify the applied version.
goose is imported by pglr-migrate alone and is not linked into the gateway,
which go list -deps checks.

Status is derived from revoked_at and expires_at rather than stored in a
column, so the two cannot disagree."
```

---

### Task 5: The Postgres store and integration conformance

**Files:**
- Create: `internal/store/postgres.go`
- Create: `internal/store/postgres_test.go`
- Modify: `Makefile` (add `test-integration`)

**Interfaces:**
- Consumes: everything from Tasks 1-4, plus `runConformance` and `testStore` from Task 3.
- Produces: `NewPostgres(ctx context.Context, databaseURL string) (*Postgres, error)`, `(*Postgres).Close()`.

- [ ] **Step 1: Write the failing integration test**

Create `internal/store/postgres_test.go`:

```go
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
```

- [ ] **Step 2: Run it to verify it fails**

Run: `go test -tags integration ./internal/store/ 2>&1 | head -5`

Expected: FAIL to build with `undefined: NewPostgres`.

- [ ] **Step 3: Write the implementation**

Create `internal/store/postgres.go`:

```go
package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgreSQL error codes this package interprets.
const (
	sqlStateUniqueViolation     = "23505"
	sqlStateForeignKeyViolation = "23503"
	sqlStateCheckViolation      = "23514"
	sqlStateUndefinedTable      = "42P01"
)

// leaseColumns is the select list every lease read shares, in the order
// scanLease expects. token_hash is read only by Authenticate, so it is not
// here.
const leaseColumns = `id, tenant_id, lease_key, backend_host, backend_port,
	backend_database, expires_at, revoked_at, created_at`

// Postgres is a Store backed by PostgreSQL. It is safe for concurrent use.
type Postgres struct {
	pool *pgxpool.Pool
}

// NewPostgres connects to databaseURL and returns a pool-backed store. The
// caller must Close it.
func NewPostgres(ctx context.Context, databaseURL string) (*Postgres, error) {
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return nil, fmt.Errorf("store: connect: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("store: ping: %w", err)
	}
	return &Postgres{pool: pool}, nil
}

// Close releases the connection pool.
func (p *Postgres) Close() { p.pool.Close() }

// CreateTenant implements Admin.
func (p *Postgres) CreateTenant(ctx context.Context, name string) (Tenant, error) {
	const q = `INSERT INTO tenants (name) VALUES ($1) RETURNING id, name, created_at`

	var t Tenant
	err := p.pool.QueryRow(ctx, q, name).Scan(&t.ID, &t.Name, &t.CreatedAt)
	if err != nil {
		return Tenant{}, p.mapError(err, fmt.Sprintf("create tenant %q", name))
	}
	return t, nil
}

// CreateLease implements Admin.
func (p *Postgres) CreateLease(ctx context.Context, in NewLease) (Lease, Token, error) {
	if err := in.Validate(); err != nil {
		return Lease{}, "", err
	}

	const q = `INSERT INTO leases
		(tenant_id, lease_key, token_hash, backend_host, backend_port, backend_database, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING ` + leaseColumns

	token := NewToken()
	var expires *time.Time
	if !in.ExpiresAt.IsZero() {
		e := in.ExpiresAt
		expires = &e
	}

	rows := p.pool.QueryRow(ctx, q,
		in.TenantID, in.Key, hashToken(token),
		in.BackendHost, in.Port(), in.BackendDatabase, expires)

	lease, err := scanLease(rows)
	if err != nil {
		return Lease{}, "", p.mapError(err, fmt.Sprintf("create lease %q", in.Key))
	}
	return lease, token, nil
}

// Lease implements Admin.
func (p *Postgres) Lease(ctx context.Context, leaseKey string) (Lease, error) {
	const q = `SELECT ` + leaseColumns + ` FROM leases WHERE lease_key = $1`

	lease, err := scanLease(p.pool.QueryRow(ctx, q, leaseKey))
	if errors.Is(err, pgx.ErrNoRows) {
		return Lease{}, fmt.Errorf("%w: %q", ErrLeaseNotFound, leaseKey)
	}
	if err != nil {
		return Lease{}, p.mapError(err, fmt.Sprintf("read lease %q", leaseKey))
	}
	return lease, nil
}

// RevokeLease implements Admin. The WHERE clause makes it idempotent: a
// second revoke matches no row and leaves the original timestamp alone.
func (p *Postgres) RevokeLease(ctx context.Context, leaseKey string) error {
	const q = `UPDATE leases SET revoked_at = now()
		WHERE lease_key = $1 AND revoked_at IS NULL`

	tag, err := p.pool.Exec(ctx, q, leaseKey)
	if err != nil {
		return p.mapError(err, fmt.Sprintf("revoke lease %q", leaseKey))
	}
	if tag.RowsAffected() == 1 {
		return nil
	}

	// No row changed: either the lease does not exist, or it was already
	// revoked. Only the first is an error.
	if _, err := p.Lease(ctx, leaseKey); err != nil {
		return err
	}
	return nil
}

// Authenticate implements LeaseAuthenticator. The token is verified before
// revocation and expiry are checked, so those are only ever disclosed to a
// caller that already holds the token.
func (p *Postgres) Authenticate(ctx context.Context, leaseKey string, token Token) (Lease, error) {
	const q = `SELECT token_hash, ` + leaseColumns + ` FROM leases WHERE lease_key = $1`

	var hash []byte
	var l Lease
	var expires, revoked *time.Time

	err := p.pool.QueryRow(ctx, q, leaseKey).Scan(
		&hash, &l.ID, &l.TenantID, &l.Key, &l.BackendHost, &l.BackendPort,
		&l.BackendDatabase, &expires, &revoked, &l.CreatedAt)

	if errors.Is(err, pgx.ErrNoRows) {
		// Compare against the dummy hash so this path's cost does not depend
		// on whether the lease exists. This equalizes the comparison, not the
		// query.
		_ = verifyToken(token, dummyHash)
		return Lease{}, fmt.Errorf("%w: %q", ErrLeaseNotFound, leaseKey)
	}
	if err != nil {
		return Lease{}, p.mapError(err, fmt.Sprintf("authenticate lease %q", leaseKey))
	}

	if !verifyToken(token, hash) {
		return Lease{}, fmt.Errorf("%w: lease %q", ErrTokenMismatch, leaseKey)
	}

	setTimes(&l, expires, revoked)
	if l.Revoked() {
		return Lease{}, fmt.Errorf("%w: lease %q", ErrLeaseRevoked, leaseKey)
	}
	if l.Expired(time.Now()) {
		return Lease{}, fmt.Errorf("%w: lease %q", ErrLeaseExpired, leaseKey)
	}
	return l, nil
}

// scanLease reads leaseColumns from a row.
func scanLease(row pgx.Row) (Lease, error) {
	var l Lease
	var expires, revoked *time.Time

	err := row.Scan(&l.ID, &l.TenantID, &l.Key, &l.BackendHost, &l.BackendPort,
		&l.BackendDatabase, &expires, &revoked, &l.CreatedAt)
	if err != nil {
		return Lease{}, err
	}
	setTimes(&l, expires, revoked)
	return l, nil
}

// setTimes copies nullable timestamps onto a Lease, leaving them zero when
// the column is NULL.
func setTimes(l *Lease, expires, revoked *time.Time) {
	if expires != nil {
		l.ExpiresAt = *expires
	}
	if revoked != nil {
		l.RevokedAt = *revoked
	}
}

// mapError translates a PostgreSQL error into one of this package's
// conditions. what describes the attempted operation.
func (p *Postgres) mapError(err error, what string) error {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return fmt.Errorf("store: %s: %w", what, err)
	}

	switch pgErr.Code {
	case sqlStateUniqueViolation:
		return fmt.Errorf("%w: %s", ErrAlreadyExists, what)
	case sqlStateForeignKeyViolation:
		return fmt.Errorf("%w: %s", ErrTenantNotFound, what)
	case sqlStateCheckViolation:
		// Validate should have caught this, so reaching here means our
		// validation has drifted from the schema. Deliberately matches no
		// sentinel: no caller should treat it as an expected condition.
		return fmt.Errorf("store: %s: check constraint %q violated, validation is out of sync with the schema: %w",
			what, pgErr.ConstraintName, err)
	default:
		return fmt.Errorf("store: %s: %w", what, err)
	}
}

// Compile-time proof that *Postgres satisfies both interfaces.
var (
	_ LeaseAuthenticator = (*Postgres)(nil)
	_ Admin              = (*Postgres)(nil)
)
```

- [ ] **Step 4: Add the Makefile target**

```make
.PHONY: test-integration
test-integration:
	go test -race -tags integration $(PKG)
```

- [ ] **Step 5: Run the integration tests to verify they pass**

```bash
make up && make migrate
make test-integration
```

Expected: PASS. The same conformance subtests as Task 3, now against PostgreSQL.

If `duplicate tenant name differing only in case` fails, the `tenants_name_key` index is missing or not on `lower(name)`. If `lease under an unknown tenant` reports something other than `ErrTenantNotFound`, the `23503` mapping is wrong.

- [ ] **Step 6: Confirm the hermetic path is still hermetic**

```bash
docker compose down
make test
```

Expected: PASS with Postgres stopped, because `postgres_test.go` is behind the tag.

- [ ] **Step 7: Verify and commit**

```bash
make up && make migrate
gofmt -l . && go vet ./... && golangci-lint run && go test -race ./... && go test -race -tags integration ./...
git add internal/store/postgres.go internal/store/postgres_test.go Makefile
git commit -m "Add the PostgreSQL lease store

Implements the store against pgx, mapping SQLSTATE 23505 to ErrAlreadyExists
and 23503 to ErrTenantNotFound. A 23514 check violation deliberately matches
no sentinel: Validate runs first, so reaching a CHECK means our validation has
drifted from the schema, which is a bug rather than an expected condition.

RevokeLease is idempotent through its WHERE clause, distinguishing an unknown
lease from an already-revoked one by a follow-up read.

The same conformance suite now runs against both implementations, so they
cannot drift. It stays behind the integration build tag, and make test is
still hermetic."
```

---

### Task 6: `CheckSchema` and daemon wiring

**Files:**
- Modify: `internal/store/migrate.go` (add `CheckSchema`)
- Create: `internal/store/migrate_test.go`
- Modify: `cmd/pglrd/main.go`
- Modify: `.env.example`

**Interfaces:**
- Consumes: `ExpectedVersion`, `ErrSchemaVersion`, `sqlStateUndefinedTable` from earlier tasks.
- Produces: `CheckSchema(ctx context.Context, databaseURL string) error`.

- [ ] **Step 1: Write the failing test**

Create `internal/store/migrate_test.go`:

```go
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
```

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./internal/store/ -run 'Migrations|CheckSchema' 2>&1 | head -5`

Expected: FAIL to build with `undefined: CheckSchema`. `TestMigrationsAreEmbedded` should already pass.

- [ ] **Step 3: Write the implementation**

Append to `internal/store/migrate.go`, and add the imports it needs:

```go
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
```

The import block for `migrate.go` becomes:

```go
import (
	"context"
	"embed"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/store/ -race -run 'Migrations|CheckSchema' -v 2>&1 | tail -10`

Expected: PASS.

- [ ] **Step 5: Wire it into the daemon**

In `cmd/pglrd/main.go`, add the import:

```go
	"github.com/chad3814/pg-lease-rate/internal/store"
```

and insert this between the `signal.NotifyContext` block and the final `return`:

```go
	// Refuse to serve against a schema this build does not understand.
	// Migrations are applied by pglr-migrate, not here.
	if err := store.CheckSchema(ctx, cfg.DatabaseURL); err != nil {
		return err
	}
```

Update the command's doc comment to mention it:

```go
// Command pglrd runs the pg-lease-rate gateway.
//
// Configuration comes from the environment; see internal/config and
// .env.example. Startup verifies that the metadata database is migrated to the
// schema version this build expects, then serves until it receives SIGINT or
// SIGTERM, then drains in-flight connections before exiting.
```

- [ ] **Step 6: Add the setting to `.env.example`**

```
# Metadata database holding tenants and leases.
PGLR_DATABASE_URL=postgres://postgres:postgres@127.0.0.1:5432/pglr?sslmode=disable
```

- [ ] **Step 7: Verify the check actually refuses**

With a migrated database, the gateway starts:

```bash
make up && make migrate
go run ./cmd/pglrd &
sleep 1
psql -h 127.0.0.1 -p 6432 -U chad -d lease_abc123 2>&1 | head -3
kill %1
```

Expected: the gateway logs `gateway listening` and `psql` still gets `FATAL: gateway has no backend attached`, unchanged from before.

With an unmigrated database, it refuses:

```bash
make migrate-down
go run ./cmd/pglrd 2>&1 | head -2
make migrate
```

Expected: exits non-zero with `pglrd: store: unexpected schema version: database is at 0, this build needs 1; run: make migrate` (or the "never been migrated" message, depending on whether goose left its bookkeeping table behind).

- [ ] **Step 8: Verify and commit**

```bash
make up && make migrate
gofmt -l . && go vet ./... && golangci-lint run && go test -race ./... && go test -race -tags integration ./... && go build -o bin/ ./cmd/...
git add internal/store/migrate.go internal/store/migrate_test.go cmd/pglrd/main.go .env.example
git commit -m "Verify the schema version at gateway startup

pglrd now refuses to serve unless the metadata database is migrated to the
version this build expects, in either direction: a database behind the binary
needs migrating, one ahead of it means an old binary is running against a new
schema.

CheckSchema opens a single connection and reads goose's version with a plain
query rather than calling into goose, so the gateway still does not link the
migration library.

A test asserts ExpectedVersion matches the number of embedded migrations,
which turns forgetting to bump the constant into a test failure rather than a
startup failure."
```

---

### Task 7: README and full verification

**Files:**
- Modify: `README.md`

**Interfaces:**
- Consumes: everything.
- Produces: nothing.

- [ ] **Step 1: Update the Status section**

Replace the paragraph beginning "Lease resolution, authentication, rate limiting, and message relay are not implemented" with:

```markdown
Lease metadata is durable. `internal/store` resolves a lease key and token to a
backend database, backed by PostgreSQL or by an in-memory implementation that
the same conformance suite exercises. The gateway verifies the schema version
at startup but does not yet consult the store: authentication, rate limiting
and message relay are still unimplemented. Nothing is stubbed: every function
present does what its documentation says.
```

Replace the "There are no external module dependencies" paragraph with:

```markdown
Two external dependencies: `github.com/jackc/pgx/v5` for PostgreSQL and
`github.com/pressly/goose/v3` for migrations. goose is imported only by
`cmd/pglr-migrate` and is not linked into the gateway. The protocol
implementation in `internal/pgwire` remains standard library only.
```

- [ ] **Step 2: Add a note to "Why two datastores"**

Append to the `**Postgres holds everything durable**` paragraph:

```markdown
The leases table holds no credentials. A lease row names a backend host, port
and database; the gateway dials it with its own credentials, so a read-only
leak of metadata does not hand over the backends.
```

- [ ] **Step 3: Update the Layout block**

```plain
cmd/pglrd/            the gateway daemon
cmd/pglr-migrate/     schema migrations
internal/config/      environment-backed configuration
internal/pgwire/      protocol framing, startup parsing, ErrorResponse
internal/gateway/     listener, startup exchange, graceful shutdown
internal/store/       tenant and lease metadata, PostgreSQL and in-memory
```

- [ ] **Step 4: Update "Running it"**

```sh
make build             # build bin/pglrd and bin/pglr-migrate
make run               # run against the default configuration
make test              # go test -race ./... -- hermetic, no Docker
make test-integration  # go test -race -tags integration ./... -- needs make up
make all               # fmt-check, vet, test, build
make lint              # golangci-lint
make up / down         # local Postgres and Redis
make migrate           # apply pending migrations
make migrate-status    # show which migrations are applied
```

- [ ] **Step 5: Update "Next steps"**

Replace item 1 with a note that it is done, and renumber:

```markdown
Step 1 is done: the lease metadata schema and store exist, keyed by the
`database` startup parameter.

In dependency order:

1. Cleartext-password authentication against a lease token.
2. Backend dial and bidirectional relay, respecting transaction boundaries.
3. Redis token bucket with a Lua check-and-decrement, injecting an
   `ErrorResponse` with SQLSTATE `53400` when a budget is exhausted.
4. Asynchronous batched usage rollups into Postgres.
5. An admin CLI over the lease and limit tables.
```

- [ ] **Step 6: Run the full verification sweep**

```bash
make up
make migrate
make fmt-check
make vet
make lint
make test
make test-integration
make build
make migrate-status
```

Expected: every one passes. Then confirm the hermetic path once more with the database down:

```bash
docker compose down
make all
```

Expected: passes with no Docker running.

- [ ] **Step 7: Commit**

```bash
git add README.md
git commit -m "Document the lease metadata store in the README

Records that step 1 is complete, retracts the no-external-dependencies claim
now that pgx and goose are in go.mod, notes that goose is not linked into the
gateway, and adds the new make targets and packages.

Also notes in the two-datastores section that the leases table holds no
credentials, which is why a lease row names a backend host, port and database
rather than a DSN."
```

- [ ] **Step 8: Report for review**

Summarize for the human partner: the branch, the commits, the verification
output, and anything that surprised you. Do not merge and do not push.

---

## Self-Review

**Spec coverage.** Every section of the spec maps to a task:

| Spec section | Task |
| --- | --- |
| Schema | 4 |
| Schema holds no secrets | 4 (migration), 7 (README) |
| Status is derived | 1 (predicates), 4 (no column) |
| SHA-256 not a KDF | 2 |
| Hash never leaves the package | 1 (no field), 3 and 5 (implementations) |
| Verification precedes status checks | 3 (regression test), 5 (implementation) |
| Store reports truth | 1 (interface doc), 3 (suite) |
| Migrations are a deploy step | 4, 6 |
| goose over golang-migrate | 4 |
| IDs are strings | 1 (types), 3 (`newID`), 4 (`gen_random_uuid`) |
| Package layout | 1-6 |
| Types | 1 |
| Extent of token redaction | 1 (`TestTokenRedacts`) |
| Interfaces | 1 |
| Errors and pg mapping | 1, 5 |
| Authenticate ordering | 3, 5 |
| Token lifecycle | 2 |
| Migrations and schema check | 4, 6 |
| Configuration | 4 (Step 5), 6 (`.env.example`) |
| Daemon wiring | 6 |
| Makefile | 4, 5 |
| Testing | 3, 5, 6 |
| Documentation | 7 |
| Verification | 7 |

**Placeholder scan.** No `TBD`, `TODO`, "add error handling", or "similar to Task N". Every code step carries the literal code. `cmd/pglr-migrate/main.go` references `cfg.DatabaseURL`, which is why adding that field is a step of the same task rather than deferred.

**Type consistency.** Checked across tasks: `Token`, `Tenant`, `Lease`, `NewLease`, `LeaseAuthenticator`, `Admin`, `DefaultBackendPort`, `MigrationsDir`, `ExpectedVersion`, `NewMemory`, `NewPostgres`, `runConformance`, `testStore`, `hashToken`, `verifyToken`, `dummyHash`, `tokenHashBytes`, `newID`, `scanLease`, `setTimes`, `mapError`. `Lease.Key` (not `LeaseKey`) is used consistently in both implementations and the suite. The four `sqlState*` constants are declared in Task 5's `postgres.go` and `sqlStateUndefinedTable` is consumed by Task 6's `migrate.go` — same package, so no import is needed, but Task 5 must land first.

One ordering constraint worth stating: **Task 6 depends on Task 5** for `sqlStateUndefinedTable`. Tasks 1-5 are strictly sequential; Task 7 is last.
