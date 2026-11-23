--- migration:up
ALTER TABLE posts
    ADD CONSTRAINT posts_body_check
    CHECK (
        btrim(
            body,
            E'\u0009\u000A\u000B\u000C\u000D\u0020\u00A0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200A\u2028\u2029\u202F\u205F\u3000\uFEFF'
        ) <> ''
        AND octet_length(body) <= 4096
    );

--- migration:down
ALTER TABLE posts
    DROP CONSTRAINT IF EXISTS posts_body_check;

--- migration:end
