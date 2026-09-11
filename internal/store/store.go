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
	// ErrInvalidTenant reports a tenant name that fails validation.
	ErrInvalidTenant = errors.New("store: invalid tenant")
	// ErrSchemaVersion reports a database whose applied migration version is
	// not the one this build expects.
	ErrSchemaVersion = errors.New("store: unexpected schema version")
)

// DefaultBackendPort is the port used when a NewLease leaves BackendPort zero.
const DefaultBackendPort = 5432

// leaseKeyPattern bounds a value that arrives from an untrusted startup
// parameter and reaches the logs. 63 bytes is PostgreSQL's identifier limit.
var leaseKeyPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,63}$`)

// uuidPattern matches the canonical 8-4-4-4-12 hex form Postgres's uuid type
// accepts. NewLease.Validate uses it so that a malformed TenantID is rejected
// in Go, in one place, before either implementation touches storage: *Memory
// has no uuid column to catch it, and *Postgres's SQLSTATE 22P02 for a
// malformed literal maps to no sentinel, so without this check the two
// implementations report different errors for the same bad input.
var uuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// maxTenantNameBytes bounds a tenant name for the same reason
// leaseKeyPattern bounds a lease key: it arrives from an untrusted operator
// input and reaches the logs.
const maxTenantNameBytes = 200

// validateTenantName reports whether name can be stored. Both
// implementations call it before any write, so the rule lives in one place.
// A name must be non-empty, at most maxTenantNameBytes, and free of ASCII
// control characters, including NUL.
func validateTenantName(name string) error {
	if name == "" {
		return fmt.Errorf("%w: name is empty", ErrInvalidTenant)
	}
	if len(name) > maxTenantNameBytes {
		return fmt.Errorf("%w: name is %d bytes, over the %d byte limit", ErrInvalidTenant, len(name), maxTenantNameBytes)
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("%w: name %q contains a control character", ErrInvalidTenant, name)
		}
	}
	return nil
}

// Token is a lease's plaintext secret. It is returned exactly once, when the
// lease is created, and is never stored: only its hash is.
//
// Token is a defined type rather than a string so that transposing the
// arguments of Authenticate is a compile error rather than an authentication
// bug, and so that String and LogValue can keep it out of logs.
type Token string

// String redacts. Call string(t) to obtain the real value.
//
// fmt derives %v, %s, %q, %x, %X, and their composition inside structs and
// slices, from Stringer, so String covers all of those. It does not cover
// %#v, which fmt derives from GoStringer instead, nor encoding/json, which
// uses encoding.TextMarshaler; see GoString and MarshalText for those. A
// numeric verb such as %d still embeds the real value in fmt's bad-verb
// message, but go vet rejects that at build time and make all runs vet.
func (t Token) String() string { return "[REDACTED]" }

// GoString redacts %#v, which fmt.GoStringer governs instead of Stringer.
func (t Token) GoString() string { return `store.Token("[REDACTED]")` }

// MarshalText redacts encoding/json and anything else built on
// encoding.TextMarshaler, none of which consult String.
func (t Token) MarshalText() ([]byte, error) { return []byte("[REDACTED]"), nil }

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
	if !uuidPattern.MatchString(n.TenantID) {
		return fmt.Errorf("%w: tenant id %q is not a UUID", ErrInvalidLease, n.TenantID)
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
