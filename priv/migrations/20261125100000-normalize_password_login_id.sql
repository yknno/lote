--- migration:up
UPDATE password_credentials
SET login_id = translate(
    btrim(login_id, E' \t\n\r'),
    'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
    'abcdefghijklmnopqrstuvwxyz'
)
WHERE login_id <> translate(
    btrim(login_id, E' \t\n\r'),
    'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
    'abcdefghijklmnopqrstuvwxyz'
);

ALTER TABLE password_credentials
    ADD CONSTRAINT password_credentials_login_id_normalized_check
    CHECK (
        octet_length(login_id) BETWEEN 1 AND 255
        AND (login_id COLLATE "C") ~ '^[a-z0-9._@-]+$'
    );

--- migration:down
ALTER TABLE password_credentials
    DROP CONSTRAINT IF EXISTS password_credentials_login_id_normalized_check;

--- migration:end
