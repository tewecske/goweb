-- Store confirmation tokens, reset tokens, and OAuth state as SHA-256 hex
-- digests, like session IDs, so a database or backup leak yields no usable
-- link. Existing rows are converted in place, so links already sent keep
-- working. The 64-character digests fit the existing columns.
UPDATE email_verification_tokens SET token = encode(sha256(convert_to(token, 'UTF8')), 'hex');
UPDATE password_reset_tokens SET token = encode(sha256(convert_to(token, 'UTF8')), 'hex');
UPDATE oauth_states SET state = encode(sha256(convert_to(state, 'UTF8')), 'hex');
