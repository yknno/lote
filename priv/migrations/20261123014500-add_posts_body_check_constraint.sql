--- migration:up
ALTER TABLE posts
    ADD CONSTRAINT posts_body_check
    CHECK (btrim(body) <> '' AND octet_length(body) <= 4096);

--- migration:down
ALTER TABLE posts
    DROP CONSTRAINT IF EXISTS posts_body_check;

--- migration:end
