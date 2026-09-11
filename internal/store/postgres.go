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

	row := p.pool.QueryRow(ctx, q,
		in.TenantID, in.Key, hashToken(token),
		in.BackendHost, in.Port(), in.BackendDatabase, expires)

	lease, err := scanLease(row)
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

// RevokeLease implements Admin. The UPDATE and the existence check are one
// statement so they share a snapshot: a lease created between them cannot make
// a revocation that changed nothing look like success. The WHERE clause makes
// it idempotent, preserving the original timestamp.
func (p *Postgres) RevokeLease(ctx context.Context, leaseKey string) error {
	const q = `WITH updated AS (
		UPDATE leases SET revoked_at = now()
		WHERE lease_key = $1 AND revoked_at IS NULL
		RETURNING 1
	)
	SELECT EXISTS(SELECT 1 FROM updated),
	       EXISTS(SELECT 1 FROM leases WHERE lease_key = $1)`

	var revokedNow, exists bool
	if err := p.pool.QueryRow(ctx, q, leaseKey).Scan(&revokedNow, &exists); err != nil {
		return p.mapError(err, fmt.Sprintf("revoke lease %q", leaseKey))
	}
	if !revokedNow && !exists {
		return fmt.Errorf("%w: %q", ErrLeaseNotFound, leaseKey)
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
