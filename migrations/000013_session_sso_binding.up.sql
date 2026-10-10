-- Client apps (GOWEB_AUTH_MODE=client) bind each local session to the Hydra
-- login session that created it. sso_sid lets a back-channel logout revoke
-- exactly those sessions; sso_id_token is the id_token_hint that Hydra
-- requires for sign-out with a return URL. Neither is a credential for this
-- app: sessions still authenticate only through their opaque cookie. Both are
-- never rendered or logged and disappear with the session row.
ALTER TABLE sessions
    ADD COLUMN sso_sid VARCHAR(128),
    ADD COLUMN sso_id_token TEXT,
    ADD CONSTRAINT sessions_sso_sid_nonempty CHECK (sso_sid IS NULL OR length(sso_sid) > 0),
    ADD CONSTRAINT sessions_sso_id_token_size CHECK (sso_id_token IS NULL OR length(sso_id_token) BETWEEN 1 AND 16384);

CREATE INDEX sessions_sso_sid_idx ON sessions (sso_sid) WHERE sso_sid IS NOT NULL;
