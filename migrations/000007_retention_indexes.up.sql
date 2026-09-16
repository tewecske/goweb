CREATE INDEX email_verification_tokens_expires_at_idx
    ON email_verification_tokens (expires_at);

CREATE INDEX password_reset_tokens_expires_at_idx
    ON password_reset_tokens (expires_at);
