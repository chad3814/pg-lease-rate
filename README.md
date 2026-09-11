# pg-lease-rate

A PostgreSQL-wire gateway that brokers leased databases and enforces per-tenant
query quotas.

A client connects with `psql` or any Postgres driver, presents a lease
identifier, and the gateway resolves it to a backend database and relays the
session while metering it. Clients need no special library: the gateway speaks
the Postgres protocol, so a rejected quota arrives as an ordinary server error.

## Status

The startup exchange works end to end. The gateway declines encryption
negotiation, parses the `StartupMessage`, validates the protocol version, and
replies with a `FATAL` `ErrorResponse` reporting that no backend is attached.

```plain
$ psql -h 127.0.0.1 -p 6432 -U chad -d lease_abc123
psql: error: connection to server at "127.0.0.1", port 6432 failed: FATAL:  gateway has no backend attached
DETAIL:  parsed a protocol 3.0 startup for user "chad", database "lease_abc123"
HINT:  lease resolution and message relay are not implemented yet
```

Lease resolution, authentication, rate limiting, and message relay are not
implemented. Nothing is stubbed: every function present does what its
documentation says.

There are no external module dependencies. The protocol implementation is
standard library only.

## Why two datastores

The split is load-bearing, not incidental.

**Redis holds the token buckets.** Quota checks happen on every query message,
so the decision has to be a single atomic round trip. A Lua script does the
check-and-decrement server side, which is the only way to make it atomic
without a lock.

**Postgres holds everything durable**: tenants, API keys, lease records, limit
policies, and rolled-up usage. None of it is in the request path. Usage is
batched and written asynchronously so that a slow write cannot stall a query.

Postgres is also the thing being proxied, which means the gateway's own
metadata and the databases it hands out live in the same engine.

## Protocol notes

Framing is uniform after startup: one type byte, a big-endian `int32` length,
then a body. The length counts its own four bytes but not the type byte.

The first message a client sends is **untyped** - length and body, no type
byte. It is one of four things, distinguished by a magic value where a version
number would be: a `StartupMessage`, an `SSLRequest`, a `GSSENCRequest`, or a
`CancelRequest`. `psql` sends `SSLRequest` first by default, so a gateway that
ignores it appears broken to the most common client.

Several type bytes mean different things by direction: `E` is Execute from a
client and `ErrorResponse` from a server; `S` is Sync or `ParameterStatus`; `D`
is Describe or `DataRow`; `C` is Close or `CommandComplete`. The `pgwire`
package therefore frames bytes and does not interpret them.

Minor protocol versions within major 3 are accepted. Postgres 18 clients may
request 3.2, and refusing them outright would be wrong.

## Design decisions

**Authentication terminates at the gateway.** SCRAM-SHA-256 cannot be
transparently proxied - the nonce exchange and channel binding both break when
a middlebox relays them. So the gateway will request a cleartext password,
treat it as the lease token, and dial the backend with its own credentials.
This is what a database-as-a-service front door does.

**Quotas are enforced at the message layer, not by parsing SQL.** Counting
`Query` and `Execute` messages counts statements. A SQL parser would be a large
dependency and a large attack surface for no gain.

**Backend connections can only be released at a transaction boundary.** The
`ReadyForQuery` status byte reports `I`, `T`, or `E`; only `I` is safe. Pooling
that ignores this hands a client someone else's open transaction.

**Open decision: fail-open or fail-closed when Redis is unavailable.**
Fail-open keeps the platform serving and stops metering, so a Redis outage
becomes an unmetered free-for-all. Fail-closed preserves the guarantee and
turns a Redis outage into a total outage. This has to be chosen deliberately
and written down here, because it is the question that gets asked first.

## Deliberately not built

- **TLS termination.** The gateway declines `SSLRequest`. Terminating TLS is a
  deployment concern that belongs in front of it.
- **SCRAM passthrough.** See above; it is not possible transparently.
- **`COPY` mode.** The protocol shifts into a sub-protocol during `COPY`, and
  handling it correctly is its own piece of work.
- **The full extended-query state machine.** Framing is enough to meter and
  relay; tracking every `Parse`/`Bind`/`Describe` interaction is not needed to
  do that.

## Layout

```plain
cmd/pglrd/            the gateway daemon
internal/config/      environment-backed configuration
internal/pgwire/      protocol framing, startup parsing, ErrorResponse
internal/gateway/     listener, startup exchange, graceful shutdown
```

## Running it

```sh
make build        # build bin/pglrd
make run          # run against the default configuration
make test         # go test -race ./...
make all          # fmt-check, vet, test, build
make up / down    # local Postgres and Redis
```

Configuration is read from the environment; see `.env.example`. Every setting
has a working default, and an unparseable value stops startup rather than
silently widening a limit.

## Next steps

In dependency order:

1. Lease metadata schema and store, keyed by the `database` startup parameter.
2. Cleartext-password authentication against a lease token.
3. Backend dial and bidirectional relay, respecting transaction boundaries.
4. Redis token bucket with a Lua check-and-decrement, injecting an
   `ErrorResponse` with SQLSTATE `53400` when a budget is exhausted.
5. Asynchronous batched usage rollups into Postgres.
6. An admin CLI over the lease and limit tables.

## License

MIT. See `LICENSE`.
