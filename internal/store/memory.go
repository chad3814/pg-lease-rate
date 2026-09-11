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

// truncateForPostgres matches the precision *Postgres actually returns: a
// timestamptz column truncates to microseconds and pgx hands back a value in
// its own Location, with no monotonic reading. Without this, *Memory stores
// a caller's ExpiresAt verbatim — nanoseconds, Location, and monotonic
// reading all included — so a caller that round-trips a timestamp and
// compares it passes against the fake and fails against the database. The
// zero value is guarded explicitly: time.Time{}.UTC().Truncate(...) must
// stay zero, since zero means "no expiry" and must not become a non-zero
// value that merely happens to render the same way.
func truncateForPostgres(t time.Time) time.Time {
	if t.IsZero() {
		return time.Time{}
	}
	return t.UTC().Truncate(time.Microsecond)
}

// CreateTenant implements Admin.
func (m *Memory) CreateTenant(_ context.Context, name string) (Tenant, error) {
	if err := validateTenantName(name); err != nil {
		return Tenant{}, err
	}

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
		ExpiresAt:       truncateForPostgres(in.ExpiresAt),
		CreatedAt:       truncateForPostgres(time.Now().UTC()),
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
	entry.lease.RevokedAt = truncateForPostgres(time.Now().UTC())
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
