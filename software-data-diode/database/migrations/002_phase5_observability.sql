CREATE TABLE IF NOT EXISTS observability_snapshots (
    id BIGSERIAL PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL,
    service TEXT NOT NULL,
    metrics JSONB NOT NULL,
    labels JSONB NOT NULL DEFAULT '{}'::jsonb
);

ALTER TABLE alerts ADD COLUMN IF NOT EXISTS acknowledged_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_observability_service_time
    ON observability_snapshots (service, timestamp DESC);

CREATE OR REPLACE VIEW latest_observability_snapshots AS
SELECT DISTINCT ON (service)
    service,
    timestamp,
    metrics,
    labels
FROM observability_snapshots
ORDER BY service, timestamp DESC;
