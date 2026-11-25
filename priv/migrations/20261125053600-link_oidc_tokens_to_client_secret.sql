--- migration:up
ALTER TABLE oidc_grants
    ADD COLUMN issued_by_secret_id BIGINT
    REFERENCES oidc_client_secrets(id) ON DELETE CASCADE;

CREATE INDEX idx_oidc_grants_issued_by_secret_id
    ON oidc_grants (issued_by_secret_id)
    WHERE issued_by_secret_id IS NOT NULL;

ALTER TABLE oidc_access_tokens
    ADD COLUMN issued_by_secret_id BIGINT
    REFERENCES oidc_client_secrets(id) ON DELETE CASCADE;

CREATE INDEX idx_oidc_access_tokens_issued_by_secret_id
    ON oidc_access_tokens (issued_by_secret_id)
    WHERE issued_by_secret_id IS NOT NULL;

--- migration:down
DROP INDEX IF EXISTS idx_oidc_access_tokens_issued_by_secret_id;
ALTER TABLE oidc_access_tokens DROP COLUMN IF EXISTS issued_by_secret_id;

DROP INDEX IF EXISTS idx_oidc_grants_issued_by_secret_id;
ALTER TABLE oidc_grants DROP COLUMN IF EXISTS issued_by_secret_id;

--- migration:end
