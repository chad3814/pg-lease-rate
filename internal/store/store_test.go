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
			"key with a dot": func(n *NewLease) { n.Key = "lease.abc" },
			"empty key":      func(n *NewLease) { n.Key = "" },
			"key over 63":    func(n *NewLease) { n.Key = strings.Repeat("a", 64) },
			"port too high":  func(n *NewLease) { n.BackendPort = 70000 },
			"negative port":  func(n *NewLease) { n.BackendPort = -1 },
			"empty host":     func(n *NewLease) { n.BackendHost = "" },
			"empty database": func(n *NewLease) { n.BackendDatabase = "" },
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
