--- migration:up
ALTER TABLE sessions
    ADD COLUMN public_id UUID NOT NULL DEFAULT gen_random_uuid(),
    ADD COLUMN user_agent TEXT NOT NULL DEFAULT '';

ALTER TABLE sessions
    ADD CONSTRAINT sessions_public_id_key UNIQUE (public_id);

--- migration:down
ALTER TABLE sessions DROP CONSTRAINT IF EXISTS sessions_public_id_key;
ALTER TABLE sessions DROP COLUMN IF EXISTS user_agent;
ALTER TABLE sessions DROP COLUMN IF EXISTS public_id;

--- migration:end
