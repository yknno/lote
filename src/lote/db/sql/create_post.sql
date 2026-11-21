INSERT INTO posts (body)
VALUES ($1)
RETURNING id, body, created_at;
