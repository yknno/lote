--- migration:up
ALTER TABLE posts
    ADD COLUMN user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE;

DROP INDEX IF EXISTS idx_posts_created_at;
CREATE INDEX idx_posts_user_id_id ON posts (user_id, id DESC);

--- migration:down
DROP INDEX IF EXISTS idx_posts_user_id_id;
CREATE INDEX idx_posts_created_at ON posts (created_at DESC);
ALTER TABLE posts DROP COLUMN IF EXISTS user_id;

--- migration:end
