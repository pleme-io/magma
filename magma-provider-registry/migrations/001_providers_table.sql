-- magma Dynamic Provider Plane — provider registry table.
-- Per theory/MAGMA-PROVIDER-PLANE.md §III (the provider sibling of
-- pangea_meta.artifacts). The DB is the durable source of truth + the
-- fleet-shared distribution surface; a (source, version, os, arch)
-- fetched once on any node is available to all.
--
-- The PrimaryKey is content-addressing's coordinate space:
-- (source, version, os, arch). `content_hash` is the BLAKE3 of `binary`,
-- verified on every read (PgRegistry::resolve) before the binary is
-- materialized to an exec path — a tampered or truncated row is a typed
-- error, never a silently-loaded plugin.
CREATE TABLE IF NOT EXISTS magma_providers (
    source        TEXT        NOT NULL,  -- "cloudflare/cloudflare", "marcfrederick/porkbun"
    version       TEXT        NOT NULL,  -- "5.12.0"
    os            TEXT        NOT NULL,  -- "linux", "darwin"
    arch          TEXT        NOT NULL,  -- "amd64", "arm64"
    binary        BYTEA       NOT NULL,  -- the tfplugin5/6 provider binary
    content_hash  TEXT        NOT NULL,  -- BLAKE3 hex of `binary`, verified on read
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (source, version, os, arch)
);
