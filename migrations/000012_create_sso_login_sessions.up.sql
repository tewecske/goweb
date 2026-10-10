-- Hydra login session IDs (the OpenID Connect "sid") seen by the provider, so
-- revoking an account's sessions can revoke each Hydra session and trigger
-- back-channel logout in every client app. The sid is an identifier, not a
-- credential: using it requires the private Hydra admin API.
CREATE TABLE sso_login_sessions (
    sid VARCHAR(128) PRIMARY KEY,
    user_id BIGINT NOT NULL,
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    CONSTRAINT sso_login_sessions_sid_nonempty CHECK (length(sid) > 0),
    CONSTRAINT sso_login_sessions_expiry_after_creation CHECK (expires_at > created_at),
    CONSTRAINT sso_login_sessions_user_id_fk FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

CREATE INDEX sso_login_sessions_user_id_idx ON sso_login_sessions (user_id);
CREATE INDEX sso_login_sessions_expires_at_idx ON sso_login_sessions (expires_at);
