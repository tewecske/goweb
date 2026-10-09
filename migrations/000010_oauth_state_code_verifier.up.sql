-- PKCE (RFC 7636) code verifier that redeems the flow's authorization code.
-- Nullable so states created before this migration still load; the service
-- rejects callbacks whose state carries no verifier.
ALTER TABLE oauth_states ADD COLUMN code_verifier VARCHAR(128);
