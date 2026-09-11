CREATE TABLE oauth_states (
    state VARCHAR(64) PRIMARY KEY,
    provider VARCHAR(32) NOT NULL,
    action VARCHAR(16) NOT NULL,
    user_id BIGINT,
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    consumed_at BIGINT,
    CONSTRAINT oauth_states_action_allowed CHECK (action IN ('sign-in', 'link')),
    CONSTRAINT oauth_states_expiry_after_creation CHECK (expires_at > created_at)
);

CREATE INDEX oauth_states_user_id_idx ON oauth_states (user_id);
CREATE INDEX oauth_states_expires_at_idx ON oauth_states (expires_at);

ALTER TABLE oauth_states
    ADD CONSTRAINT oauth_states_user_id_fk
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE;
