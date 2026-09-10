ALTER TABLE sessions
    ADD CONSTRAINT sessions_user_id_fk
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE;

ALTER TABLE oauth_identities
    ADD CONSTRAINT oauth_identities_user_id_fk
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE;

ALTER TABLE email_verification_tokens
    ADD CONSTRAINT email_verification_tokens_user_id_fk
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE;

ALTER TABLE password_reset_tokens
    ADD CONSTRAINT password_reset_tokens_user_id_fk
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE;

ALTER TABLE guest_claim_codes
    ADD CONSTRAINT guest_claim_codes_user_id_fk
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE;

ALTER TABLE login_attempts
    ADD CONSTRAINT login_attempts_user_id_fk
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE SET NULL;

ALTER TABLE audit_log
    ADD CONSTRAINT audit_log_actor_user_id_fk
    FOREIGN KEY (actor_user_id) REFERENCES users (id) ON DELETE SET NULL;

ALTER TABLE usage_events
    ADD CONSTRAINT usage_events_user_id_fk
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE SET NULL;

ALTER TABLE groups
    ADD CONSTRAINT groups_created_by_fk
    FOREIGN KEY (created_by) REFERENCES users (id) ON DELETE SET NULL;

ALTER TABLE group_members
    ADD CONSTRAINT group_members_group_id_fk
    FOREIGN KEY (group_id) REFERENCES groups (id) ON DELETE CASCADE;

ALTER TABLE group_members
    ADD CONSTRAINT group_members_user_id_fk
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE;
