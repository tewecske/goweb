ALTER TABLE usage_events
    ADD COLUMN trace_id VARCHAR(32);

CREATE INDEX usage_events_trace_id_idx ON usage_events (trace_id);
