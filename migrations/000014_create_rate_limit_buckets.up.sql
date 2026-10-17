-- Fixed-window attempt counters for sign-in, sign-up, password reset, and the
-- other rate-limited actions, shared by every instance of an app so a restart
-- or a second instance does not reset or multiply the budgets. Keys (email
-- addresses, client addresses) are stored only as a SHA-256 hash plus a
-- redacted hint for the administrator view. Times are Unix milliseconds.
CREATE TABLE rate_limit_buckets (
    scope VARCHAR(64) NOT NULL,
    action VARCHAR(255) NOT NULL,
    key_hash BYTEA NOT NULL,
    key_hint VARCHAR(255) NOT NULL,
    hit_count INTEGER NOT NULL,
    started_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    PRIMARY KEY (scope, action, key_hash),
    CONSTRAINT rate_limit_buckets_scope_nonempty CHECK (length(scope) > 0),
    CONSTRAINT rate_limit_buckets_action_nonempty CHECK (length(action) > 0),
    CONSTRAINT rate_limit_buckets_count_positive CHECK (hit_count > 0),
    CONSTRAINT rate_limit_buckets_expiry_after_start CHECK (expires_at > started_at)
);

CREATE INDEX rate_limit_buckets_expires_at_idx ON rate_limit_buckets (expires_at);
