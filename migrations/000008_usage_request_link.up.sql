ALTER TABLE usage_events
    ADD COLUMN request_id VARCHAR(64);

CREATE INDEX usage_events_request_id_idx ON usage_events (request_id);
