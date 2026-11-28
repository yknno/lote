--- migration:up
ALTER TABLE oidc_clients
    ADD COLUMN cimd_expires_at TIMESTAMPTZ;

UPDATE oidc_clients
SET visibility = 'public',
    cimd_expires_at = COALESCE(cimd_expires_at, NOW())
WHERE kind = 'cimd';

ALTER TABLE oidc_clients
    ADD CONSTRAINT oidc_clients_cimd_check
        CHECK (
            (kind = 'cimd' AND visibility = 'public' AND cimd_expires_at IS NOT NULL)
            OR (kind <> 'cimd' AND cimd_expires_at IS NULL)
        );

CREATE INDEX idx_oidc_clients_cimd_expires_at
    ON oidc_clients (cimd_expires_at)
    WHERE kind = 'cimd';

CREATE INDEX idx_oidc_consents_client_ref_id
    ON oidc_consents (client_ref_id);

--- migration:down
DROP INDEX IF EXISTS idx_oidc_consents_client_ref_id;
DROP INDEX IF EXISTS idx_oidc_clients_cimd_expires_at;

ALTER TABLE oidc_clients
    DROP CONSTRAINT IF EXISTS oidc_clients_cimd_check;

ALTER TABLE oidc_clients
    DROP COLUMN IF EXISTS cimd_expires_at;

--- migration:end
