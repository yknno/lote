--- migration:up
CREATE UNLOGGED TABLE rate_limits (
    key TEXT PRIMARY KEY,
    tat_ms BIGINT NOT NULL
);

CREATE INDEX idx_rate_limits_tat_ms ON rate_limits (tat_ms);

--- migration:down
DROP TABLE IF EXISTS rate_limits;

--- migration:end
