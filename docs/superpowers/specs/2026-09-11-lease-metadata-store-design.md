# Lease metadata schema and store

Design for step 1 of the pg-lease-rate roadmap: the durable schema for tenants
and leases, and the Go package that reads and writes it.

- **Date:** 2026-09-11
- **Branch:** `feature/lease-store`
- **Status:** approved in brainstorming, not yet implemented

## Goal

Give the gateway a way to answer one question: *does this lease key plus this
token identify an active lease, and which backend database does it point at?*

The gateway does not yet ask that question. This step ships the schema, the
store, the migration tooling, and a startup schema check. Step 2 adds the
protocol work that calls it.

## Scope

**In:**

- A `tenants` table and a `leases` table, with one goose migration.
- `internal/store`: types, two interfaces, a Postgres implementation, an
  in-memory implementation, and one conformance suite run against both.
- Lease token generation, hashing, and constant-time verification.
- `cmd/pglr-migrate`: a binary that applies and reports migrations.
- A schema-version check in `cmd/pglrd` that refuses to start on a mismatch.

**Out, and which step owns it:**

| Deferred | Step |
| --- | --- |
| Limit policies | 4, where the token-bucket design determines their shape |
| Usage rollups | 5 |
| API keys | 6, with the admin CLI |
| Cleartext-password auth exchange | 2 |
| Backend dial and relay | 3 |
| Any change to `internal/gateway` or `internal/pgwire` | 2 |

`internal/gateway/server.go` is untouched by this step. It still replies
`FATAL 0A000 gateway has no backend attached`.

## Decisions

Each of these was chosen deliberately during brainstorming; the reasoning is
recorded so a later reader does not have to re-derive it.

### Schema holds no secrets

The leases table stores `backend_host`, `backend_port`, and
`backend_database` — not a DSN. A DSN would embed the backend password, making
the leases table a table of secrets, so a read-only leak of metadata would
hand over every backend. The README already specifies that the gateway dials
backends "with its own credentials", so the row only needs to name *which*
database and the credentials come from gateway configuration.

The limitation is that every backend shares one credential set. That matches
the README's design. If per-lease credentials are ever needed, they should
arrive as a reference to a secret store, not as a plaintext column.

### Status is derived, not stored

There is no `status` column. A lease is active when
`revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now())`. A stored
enum can disagree with the timestamps; a derived predicate cannot.

### Tokens are hashed with SHA-256, not a KDF

A lease token is 32 bytes from `crypto/rand`, base64url-encoded. The stored
value is its SHA-256, compared with `crypto/subtle.ConstantTimeCompare`.

Not bcrypt or argon2, because:

- A KDF exists to make *guessing* expensive. At 256 bits of entropy there is
  nothing to guess.
- A KDF would add 50–100 ms to every client connection, in the connection
  path.
- No salt is needed for the same reason: precomputation is meaningless against
  256-bit random input.
- An HMAC with a server-side pepper was considered and rejected: it would
  prevent an attacker with the database from verifying guesses, but there are
  no guesses to verify, so it adds key management for no threat reduction.

This is how GitHub, Stripe, and AWS treat API keys.

### The token hash never leaves the package

`Authenticate` takes a token and returns a `Lease`. The `Lease` struct has no
hash field and there is no accessor for one. A caller therefore cannot compare
a hash incorrectly, because it cannot obtain one.

### Token verification precedes the status checks

`Authenticate` verifies the token before testing revocation and expiry. This
means revoked and expired are only ever reported to a caller who has already
proven they hold the token, so step 2 can safely surface "your lease expired"
to a client while revealing nothing on a bad token.

### The store reports truth; the protocol layer decides what to reveal

`Authenticate` returns distinct errors so logs and metrics can tell "no such
lease" from "wrong token". Step 2's gateway must collapse `ErrLeaseNotFound`
and `ErrTokenMismatch` into a single client-facing `FATAL 28P01`, because
distinguishing them to a client is a lease-key enumeration oracle.

### Migrations are a deploy step, not a startup side effect

`cmd/pglr-migrate` applies migrations. `cmd/pglrd` only reads the applied
version and refuses to boot on a mismatch. A bad migration therefore fails a
deploy rather than taking the service down, and several gateways booting
concurrently cannot race.

### goose over golang-migrate

Measured with `go list -deps`, excluding pgx and its transitive dependencies
which are needed either way: goose adds 4 modules (`goose/v3`,
`mfridman/interpolate`, `sethvargo/go-retry`, `go.uber.org/multierr`);
golang-migrate would add 2 (`migrate/v4`, `jackc/pgerrcode`). goose is the
heavier option and was still chosen, for three reasons:

1. **No dirty state.** golang-migrate marks the database dirty on a failed
   migration and refuses every subsequent command until a manual
   `migrate force` plus hand repair. goose simply does not record the version,
   so a failed migration rolls back and can be retried.
2. **Explicit transaction control.** goose wraps each migration in a
   transaction by default and offers `-- +goose NO TRANSACTION` for statements
   Postgres cannot run transactionally, such as `CREATE INDEX CONCURRENTLY`.
   golang-migrate's Postgres driver controls this through `x-multi-statement`
   DSN parameters, which is a sharper edge.
3. **Go migrations.** goose can register a Go function as a migration, which
   steps 5 and 6 may want for a backfill with real logic.

This ends the README's "no external module dependencies" claim; the README is
updated accordingly.

### IDs are strings

Go has no standard-library UUID type and `google/uuid` is not worth a
dependency. IDs are `string`. Postgres generates them with
`DEFAULT gen_random_uuid()` and `RETURNING`; the in-memory store mints v4
UUIDs with a short `crypto/rand` helper. This keeps pgx entirely out of
`memory.go`, so the hermetic test path links no driver.

Surrogate UUID primary keys with `lease_key` as a unique natural key, because
step 5's usage rollups will reference leases and a 16-byte stable key beats
repeating a 63-byte text key across a high-volume table.

## Schema

`internal/store/migrations/00001_tenants_and_leases.sql`:

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

Notes:

- `token_hash` is `bytea` because it is 32 raw SHA-256 bytes; no encoding
  question arises. The length check makes a wrong-sized write fail loudly.
- The `lease_key` regex bounds a value that arrives from an untrusted startup
  parameter and reaches the logs. 63 bytes is Postgres's own identifier limit.
- `ON DELETE RESTRICT` so deleting a tenant cannot silently drop live leases.
- No `updated_at`; nothing mutates these rows except revocation, which has its
  own column.
- `gen_random_uuid()` is built in from PostgreSQL 13. `docker-compose.yml`
  pins `postgres:17-alpine`.

## Package layout

```
internal/store/
  store.go            Tenant, Lease, Token, NewLease; interfaces; sentinel errors
  token.go            generate / hash / constant-time verify
  postgres.go         *Postgres (pgxpool)
  memory.go           *Memory (map + mutex, no external deps)
  migrate.go          embed.FS, ExpectedVersion, CheckSchema
  migrations/
    00001_tenants_and_leases.sql
  store_test.go       conformance suite, NO build tag
  memory_test.go      suite against *Memory (always runs)
  postgres_test.go    suite against *Postgres (//go:build integration)
  token_test.go       token behaviour (always runs)

cmd/pglr-migrate/
  main.go             up / down / status
```

Named `store` rather than `lease` because it also owns tenants, migrations,
and the schema check.

## Types

```go
// Token is a lease's plaintext secret. Returned exactly once, at creation,
// and never stored.
type Token string

// String redacts. Call string(t) to obtain the real value.
func (t Token) String() string { return "[REDACTED]" }

// LogValue redacts in slog output.
func (t Token) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

type Tenant struct {
    ID        string
    Name      string
    CreatedAt time.Time
}

type Lease struct {
    ID              string
    TenantID        string
    Key             string // the "database" startup parameter
    BackendHost     string
    BackendPort     int
    BackendDatabase string
    ExpiresAt       time.Time // zero means no expiry
    RevokedAt       time.Time // zero means not revoked
    CreatedAt       time.Time
}

func (l Lease) Revoked() bool              { return !l.RevokedAt.IsZero() }
func (l Lease) Expired(now time.Time) bool { return !l.ExpiresAt.IsZero() && !now.Before(l.ExpiresAt) }
func (l Lease) Active(now time.Time) bool  { return !l.Revoked() && !l.Expired(now) }

type NewLease struct {
    TenantID        string
    Key             string
    BackendHost     string
    BackendPort     int       // zero defaults to 5432
    BackendDatabase string
    ExpiresAt       time.Time // zero means no expiry
}

// Validate enforces the lease-key charset and length and the port range.
func (n NewLease) Validate() error
```

`Token` as a defined type does two jobs. It makes transposing the arguments of
`Authenticate(ctx, leaseKey, token)` a compile error rather than an
authentication bug, and its `String`/`LogValue` methods keep it out of logs.

`Expired` takes `now` as a parameter rather than calling `time.Now()`, so it is
testable without injecting a clock — the same approach as
`config.Load(os.Getenv)`.

### Extent of token redaction

Verified empirically. A `Token` renders as `[REDACTED]` under `%v`, `%s`, `%q`,
`%x`, `fmt.Sprint`, `fmt.Println`, `%+v` inside a struct, and `slog`.

One gap: a numeric verb such as `%d` produces fmt's bad-verb message,
`%!d(store.Token=<value>)`, which embeds the real value. `go vet` rejects that
at build time and `make all` runs `vet`, so the redaction holds for every verb
that compiles clean. It is not an absolute guarantee and should not be
described as one.

## Interfaces

```go
// LeaseAuthenticator is all the gateway needs. Step 2 depends on this and
// nothing more.
type LeaseAuthenticator interface {
    Authenticate(ctx context.Context, leaseKey string, token Token) (Lease, error)
}

// Admin is for tests and the step-6 CLI. The gateway must not depend on it.
type Admin interface {
    // CreateTenant returns ErrAlreadyExists if the name is taken, compared
    // case-insensitively.
    CreateTenant(ctx context.Context, name string) (Tenant, error)

    // CreateLease validates in, generates a token, stores its hash, and
    // returns the plaintext token exactly once. Returns ErrInvalidLease for a
    // bad key or port, ErrTenantNotFound for an unknown TenantID, and
    // ErrAlreadyExists for a duplicate key.
    CreateLease(ctx context.Context, in NewLease) (Lease, Token, error)

    // Lease reads a lease without authenticating it. It returns revoked and
    // expired leases as ordinary results, with RevokedAt and ExpiresAt set, so
    // an operator can inspect them. Only an absent row is ErrLeaseNotFound.
    Lease(ctx context.Context, leaseKey string) (Lease, error)

    // RevokeLease sets revoked_at. It is idempotent: revoking an
    // already-revoked lease succeeds and leaves the original timestamp
    // unchanged. An unknown key is ErrLeaseNotFound.
    RevokeLease(ctx context.Context, leaseKey string) error
}
```

There is no exported combined interface. The conformance suite declares an
unexported `interface { LeaseAuthenticator; Admin }` in the test file, so the
public surface stays two narrow interfaces.

`CreateLease` returns the plaintext `Token` once. There is no way to read it
back.

`Lease` deliberately does not filter by status, and `Authenticate`
deliberately does. They serve different callers: an operator inspecting a
lease needs to see that it is revoked, whereas a connecting client must be
refused.

Both implementations are safe for concurrent use. `*Postgres` delegates to
`pgxpool`, which is; `*Memory` guards its maps with a `sync.RWMutex`.

## Errors

```go
var (
    ErrLeaseNotFound  = errors.New("store: lease not found")
    ErrTokenMismatch  = errors.New("store: lease token does not match")
    ErrLeaseRevoked   = errors.New("store: lease revoked")
    ErrLeaseExpired   = errors.New("store: lease expired")
    ErrTenantNotFound = errors.New("store: tenant not found")
    ErrAlreadyExists  = errors.New("store: already exists")
    ErrInvalidLease   = errors.New("store: invalid lease")
    ErrSchemaVersion  = errors.New("store: unexpected schema version")
)
```

Package-level sentinels wrapped with `%w` at call sites, matching
`pgwire.ErrMalformed` and `gateway.ErrNotListening`.

### Postgres error mapping

Via `*pgconn.PgError.Code`:

| SQLSTATE | Condition | Mapped to |
| --- | --- | --- |
| `23505` | unique_violation | `ErrAlreadyExists` |
| `23503` | foreign_key_violation | `ErrTenantNotFound` |
| `23514` | check_violation | a plain wrapped error, no sentinel |
| `42P01` | undefined_table on `goose_db_version` | `ErrSchemaVersion` |

`NewLease.Validate()` enforces the same rules in Go before any query runs, so
the SQL `CHECK` constraints are defence in depth. A `23514` therefore means
our validation has drifted from the schema — a bug, not user error. It is
returned as `fmt.Errorf("store: check constraint %q violated, validation is
out of sync with the schema: %w", pgErr.ConstraintName, pgErr)` and matches no
sentinel deliberately, so no caller can handle it as an expected condition.

`*Memory` reproduces the same validation and the same errors. The conformance
suite enforces this, because it is one test body run against both. `*Memory`
also performs the dummy-hash comparison on the not-found path — not because
timing matters for an in-memory fake, but so the two implementations have no
behavioural difference the suite could miss.

## Authenticate

```
1. SELECT the row by lease_key
2. if absent  -> compare the presented token against a fixed dummy hash in
                 constant time, then return ErrLeaseNotFound
3. constant-time compare against the stored hash
   mismatch   -> ErrTokenMismatch
4. only now:  Revoked()    -> ErrLeaseRevoked
5.            Expired(now) -> ErrLeaseExpired
6. return the lease
```

Step 2 keeps the comparison cost constant whether or not the lease exists.
This equalizes the comparison, not the query: a hit and a miss have different
database costs, and no claim is made that the timing channel is closed. The
goal is not to hand out a trivially measurable oracle.

## Token lifecycle

```go
const tokenBytes = 32 // 256 bits

// NewToken returns a fresh random lease token.
//
// crypto/rand.Read is documented never to return an error; it crashes the
// process irrecoverably if the OS entropy source fails. So this cannot fail
// and returns no error.
func NewToken() Token {
    b := make([]byte, tokenBytes)
    _, _ = rand.Read(b)
    return Token(base64.RawURLEncoding.EncodeToString(b))
}

func hashToken(t Token) []byte {
    sum := sha256.Sum256([]byte(t))
    return sum[:]
}

func verifyToken(t Token, want []byte) bool {
    return subtle.ConstantTimeCompare(hashToken(t), want) == 1
}
```

`base64.RawURLEncoding` yields 43 characters with no padding, safe to place in
a DSN password field.

## Migrations and the schema check

```go
//go:embed migrations/*.sql
var Migrations embed.FS

// ExpectedVersion is the schema version this build requires. Bump it with
// every new migration.
const ExpectedVersion int64 = 1

// CheckSchema opens one connection, compares the applied version against
// ExpectedVersion, and closes it. Any mismatch is ErrSchemaVersion, in both
// directions: a database behind this build needs migrating, and a database
// ahead of it means an older binary is running against a newer schema. Both
// are refusals, and the error message says which case it is.
func CheckSchema(ctx context.Context, databaseURL string) error

// NewPostgres returns a pool-backed store, for integration tests and step 2.
func NewPostgres(ctx context.Context, databaseURL string) (*Postgres, error)
```

`CheckSchema` reads the version with a plain query rather than calling into
goose, so **only `cmd/pglr-migrate` imports goose** and it is never linked
into `pglrd`.

goose v3.28.0 creates its bookkeeping table as:

```sql
CREATE TABLE goose_db_version (
    id         integer PRIMARY KEY GENERATED BY DEFAULT AS IDENTITY,
    version_id bigint NOT NULL,
    is_applied boolean NOT NULL,
    tstamp     timestamp NOT NULL DEFAULT now()
)
```

The version query is goose's own `GetLatestVersion`:

```sql
SELECT max(version_id) FROM goose_db_version
```

No `is_applied` filter, because `goose down` deletes the row rather than
flipping the flag. Using goose's own query keeps this correct by construction.

A missing table (`42P01`) is reported as `ErrSchemaVersion` wrapped with a
message naming `make migrate`, not as a raw SQL error.

Migrations use goose's **sequential** versioning, not timestamps:
`00001_tenants_and_leases.sql`, then `00002_...`, and so on. Sequential
numbers keep `ExpectedVersion` readable as a small integer and make ordering
obvious in a directory listing. The cost — merge conflicts when two branches
add a migration at once — is not a concern for a single-author repository, and
`goose fix` exists if it becomes one.

## Configuration

One new setting:

```
PGLR_DATABASE_URL=postgres://postgres:postgres@127.0.0.1:5432/pglr?sslmode=disable
```

Defaulted to match `docker-compose.yml`, consistent with the README's promise
that every setting has a working default. It works locally and fails fast with
connection-refused anywhere else.

`internal/config` keeps the DSN as an opaque string and does not parse it, so
that package stays dependency-free. `store` parses it and produces the useful
error.

Credentials for dialing backends belong to step 3 and are not added here.

## Daemon wiring

```go
if err := store.CheckSchema(ctx, cfg.DatabaseURL); err != nil {
    return err
}
return gateway.New(cfg, logger).ListenAndServe(ctx)
```

A package function taking a URL, deliberately not a held pool. This step
verifies connectivity and schema at boot and releases the connection. Step 2
is the change that introduces the pool and hands it to the gateway, which
keeps this step's diff free of an unused field.

## Makefile

```make
build:            go build -o bin/ ./cmd/...      # both binaries
test-integration: go test -race -tags integration ./...
migrate:          go run ./cmd/pglr-migrate up
migrate-status:   go run ./cmd/pglr-migrate status
migrate-down:     go run ./cmd/pglr-migrate down
```

`make all` stays hermetic: `fmt-check vet test build`, no Docker.
`test-integration` is opt-in after `make up`.

## Testing

`store_test.go` holds the conformance suite with no build tag, so it compiles
into both the hermetic and the integration path:

```go
type testStore interface {
    LeaseAuthenticator
    Admin
}

func runConformance(t *testing.T, newStore func(*testing.T) testStore)
```

Cases:

| Case | Expected |
| --- | --- |
| authenticate with the created token | returns the lease |
| unknown lease key | `ErrLeaseNotFound` |
| wrong token | `ErrTokenMismatch` |
| revoked lease, correct token | `ErrLeaseRevoked` |
| expired lease, correct token | `ErrLeaseExpired` |
| revoked lease, wrong token | `ErrTokenMismatch`, not `ErrLeaseRevoked` |
| duplicate lease key | `ErrAlreadyExists` |
| duplicate tenant name, different case | `ErrAlreadyExists` |
| lease under an unknown tenant | `ErrTenantNotFound` |
| invalid lease key | `ErrInvalidLease` |
| invalid backend port | `ErrInvalidLease` |
| zero backend port | defaults to 5432 |
| `Lease()` on a revoked lease | returns the row with `RevokedAt` set |
| `Lease()` on an unknown key | `ErrLeaseNotFound` |
| `RevokeLease` twice | second call succeeds, timestamp unchanged |
| `RevokeLease` on an unknown key | `ErrLeaseNotFound` |
| two `CreateLease` calls | tokens differ |

The "revoked lease, wrong token" case pins the ordering decision: it would
pass trivially if the status checks ran first, and it is the regression test
for that.

`memory_test.go` runs the suite against `*Memory` on every `make test`.

`postgres_test.go` carries `//go:build integration`, runs the same suite
against `*Postgres`, and truncates both tables between runs. If the database
is unreachable it **fails** with a message naming `make up` rather than
skipping: passing `-tags integration` is an explicit request, and a silent
skip is how integration suites rot.

`token_test.go` covers token length and uniqueness, hash determinism, verify
accept and reject, and explicit assertions that `%v`, `%s`, `%q`, and `slog`
output all redact.

## Documentation

The README is updated in four places:

- **Status** — the store exists; the gateway still has no backend attached.
- **Why two datastores** — note that the leases table holds no secrets.
- **Layout** — add `internal/store/` and `cmd/pglr-migrate/`.
- **Next steps** — step 1 done; also retract the "no external module
  dependencies" claim, which goose and pgx end.

## Verification

Per the repository's standard, this work is not done until all of these pass:

```sh
make fmt-check
make vet
make lint             # golangci-lint 2.13.2
make test             # hermetic, no Docker
make up
make migrate
make test-integration
make build
```
