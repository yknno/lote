--- migration:up
DROP INDEX IF EXISTS idx_posts_user_id_id;

ALTER TABLE posts
    ADD COLUMN id_uuid UUID NOT NULL DEFAULT uuidv7();

ALTER TABLE posts DROP CONSTRAINT posts_pkey;
ALTER TABLE posts DROP COLUMN id;
ALTER TABLE posts RENAME COLUMN id_uuid TO id;
ALTER TABLE posts ADD PRIMARY KEY (id);

CREATE INDEX idx_posts_user_id_id ON posts (user_id, id DESC);

--- migration:down
DROP INDEX IF EXISTS idx_posts_user_id_id;

ALTER TABLE posts
    ADD COLUMN id_int BIGINT GENERATED ALWAYS AS IDENTITY;

ALTER TABLE posts DROP CONSTRAINT posts_pkey;
ALTER TABLE posts DROP COLUMN id;
ALTER TABLE posts RENAME COLUMN id_int TO id;
ALTER TABLE posts ADD PRIMARY KEY (id);

CREATE INDEX idx_posts_user_id_id ON posts (user_id, id DESC);

--- migration:end
