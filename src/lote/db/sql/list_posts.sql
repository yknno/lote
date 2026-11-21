SELECT id, body, created_at
FROM posts
ORDER BY created_at DESC, id DESC
LIMIT $1;
