--- migration:up
ALTER TABLE users
    ADD COLUMN public_id UUID NOT NULL DEFAULT gen_random_uuid();

ALTER TABLE users
    ADD CONSTRAINT users_public_id_key UNIQUE (public_id);

CREATE TABLE oidc_clients (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    client_id TEXT NOT NULL UNIQUE
        CHECK (btrim(client_id) <> '' AND octet_length(client_id) <= 512),
    owner_user_id BIGINT REFERENCES users(id) ON DELETE CASCADE,
    kind TEXT NOT NULL
        CHECK (kind IN ('subordinate_bot', 'confidential_app', 'public_app', 'cimd')),
    visibility TEXT NOT NULL DEFAULT 'private'
        CHECK (visibility IN ('private', 'public')),
    application_type TEXT NOT NULL DEFAULT 'web'
        CHECK (application_type IN ('web', 'native')),
    name TEXT NOT NULL
        CHECK (btrim(name) <> '' AND char_length(name) <= 100),
    redirect_uris TEXT[] NOT NULL DEFAULT '{}',
    allowed_scopes TEXT[] NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT oidc_clients_bot_private_check
        CHECK (kind <> 'subordinate_bot' OR visibility = 'private'),
    CONSTRAINT oidc_clients_owner_check
        CHECK ((kind = 'cimd' AND owner_user_id IS NULL) OR (kind <> 'cimd' AND owner_user_id IS NOT NULL))
);

CREATE INDEX idx_oidc_clients_owner_user_id ON oidc_clients (owner_user_id);

CREATE TABLE oidc_client_secrets (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id UUID NOT NULL DEFAULT gen_random_uuid() UNIQUE,
    client_ref_id BIGINT NOT NULL REFERENCES oidc_clients(id) ON DELETE CASCADE,
    label TEXT NOT NULL DEFAULT ''
        CHECK (char_length(label) <= 100),
    secret_prefix TEXT NOT NULL,
    secret_hash BYTEA NOT NULL UNIQUE
        CHECK (octet_length(secret_hash) = 32),
    expires_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_oidc_client_secrets_client_ref_id ON oidc_client_secrets (client_ref_id);

CREATE TABLE oidc_consents (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id UUID NOT NULL DEFAULT gen_random_uuid() UNIQUE,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_ref_id BIGINT NOT NULL REFERENCES oidc_clients(id) ON DELETE CASCADE,
    scopes TEXT[] NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT oidc_consents_user_client_key UNIQUE (user_id, client_ref_id)
);

CREATE INDEX idx_oidc_consents_user_id ON oidc_consents (user_id);

CREATE TABLE oidc_grants (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id UUID NOT NULL DEFAULT gen_random_uuid() UNIQUE,
    consent_id BIGINT NOT NULL REFERENCES oidc_consents(id) ON DELETE CASCADE,
    scopes TEXT[] NOT NULL,
    audience TEXT NOT NULL,
    user_agent TEXT NOT NULL DEFAULT '',
    last_used_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_oidc_grants_consent_id ON oidc_grants (consent_id);
CREATE INDEX idx_oidc_grants_expires_at ON oidc_grants (expires_at);

CREATE TABLE oidc_auth_codes (
    code_hash BYTEA PRIMARY KEY
        CHECK (octet_length(code_hash) = 32),
    grant_id BIGINT NOT NULL REFERENCES oidc_grants(id) ON DELETE CASCADE,
    redirect_uri TEXT NOT NULL,
    code_challenge TEXT NOT NULL,
    nonce TEXT,
    used_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_oidc_auth_codes_grant_id ON oidc_auth_codes (grant_id);
CREATE INDEX idx_oidc_auth_codes_expires_at ON oidc_auth_codes (expires_at);

CREATE TABLE oidc_access_tokens (
    token_hash BYTEA PRIMARY KEY
        CHECK (octet_length(token_hash) = 32),
    grant_id BIGINT NOT NULL REFERENCES oidc_grants(id) ON DELETE CASCADE,
    scopes TEXT[] NOT NULL,
    audience TEXT NOT NULL,
    last_used_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_oidc_access_tokens_grant_id ON oidc_access_tokens (grant_id);
CREATE INDEX idx_oidc_access_tokens_expires_at ON oidc_access_tokens (expires_at);

CREATE TABLE oidc_refresh_tokens (
    token_hash BYTEA PRIMARY KEY
        CHECK (octet_length(token_hash) = 32),
    grant_id BIGINT NOT NULL REFERENCES oidc_grants(id) ON DELETE CASCADE,
    used_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_oidc_refresh_tokens_grant_id ON oidc_refresh_tokens (grant_id);
CREATE INDEX idx_oidc_refresh_tokens_expires_at ON oidc_refresh_tokens (expires_at);

--- migration:down
DROP TABLE IF EXISTS oidc_refresh_tokens;
DROP TABLE IF EXISTS oidc_access_tokens;
DROP TABLE IF EXISTS oidc_auth_codes;
DROP TABLE IF EXISTS oidc_grants;
DROP TABLE IF EXISTS oidc_consents;
DROP TABLE IF EXISTS oidc_client_secrets;
DROP TABLE IF EXISTS oidc_clients;

ALTER TABLE users DROP CONSTRAINT IF EXISTS users_public_id_key;
ALTER TABLE users DROP COLUMN IF EXISTS public_id;

--- migration:end
