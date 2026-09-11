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
-- Destroys all tenant and lease data.
DROP TABLE leases;
DROP TABLE tenants;
