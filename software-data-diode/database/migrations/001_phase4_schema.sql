CREATE TABLE IF NOT EXISTS accepted_telemetry (
    id BIGSERIAL PRIMARY KEY,
    event_id UUID NOT NULL UNIQUE,
    message_id UUID NOT NULL UNIQUE,
    device_id TEXT NOT NULL,
    sequence_number BIGINT NOT NULL,
    priority TEXT NOT NULL,
    telemetry_type TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    received_at TIMESTAMPTZ NOT NULL,
    payload JSONB NOT NULL,
    payload_hash CHAR(64) NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_telemetry_device_time
    ON accepted_telemetry (device_id, received_at DESC);
CREATE INDEX IF NOT EXISTS idx_telemetry_type_time
    ON accepted_telemetry (telemetry_type, received_at DESC);

CREATE TABLE IF NOT EXISTS rejected_messages (
    id BIGSERIAL PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    reason TEXT NOT NULL,
    message_id UUID,
    device_id TEXT,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE IF NOT EXISTS security_events (
    event_id UUID PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL,
    event_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    source_devices TEXT[] NOT NULL,
    evidence JSONB NOT NULL,
    description TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS anomalies (
    anomaly_id UUID PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL,
    message_id UUID NOT NULL,
    device_id TEXT NOT NULL,
    detector TEXT NOT NULL,
    metric TEXT NOT NULL,
    observed_value DOUBLE PRECISION NOT NULL,
    expected_value DOUBLE PRECISION,
    score DOUBLE PRECISION,
    severity TEXT NOT NULL,
    explanation TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_anomalies_device_time
    ON anomalies (device_id, timestamp DESC);

CREATE TABLE IF NOT EXISTS alerts (
    alert_id UUID PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL,
    source_devices TEXT[] NOT NULL,
    alert_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    evidence JSONB NOT NULL,
    description TEXT NOT NULL,
    acknowledged_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_alerts_severity_time
    ON alerts (severity, timestamp DESC);

CREATE TABLE IF NOT EXISTS experiment_metadata (
    experiment_id UUID PRIMARY KEY,
    name TEXT NOT NULL,
    started_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ,
    configuration JSONB NOT NULL DEFAULT '{}'::jsonb,
    results JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE IF NOT EXISTS performance_metrics (
    id BIGSERIAL PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    service TEXT NOT NULL,
    metric_name TEXT NOT NULL,
    metric_value DOUBLE PRECISION NOT NULL,
    labels JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_performance_service_time
    ON performance_metrics (service, timestamp DESC);

CREATE OR REPLACE VIEW device_telemetry_summary AS
SELECT
    device_id,
    telemetry_type,
    COUNT(*) AS message_count,
    MAX(received_at) AS last_received_at,
    MAX(sequence_number) AS latest_sequence_number
FROM accepted_telemetry
GROUP BY device_id, telemetry_type;

CREATE OR REPLACE VIEW alert_severity_summary AS
SELECT
    severity,
    alert_type,
    COUNT(*) AS alert_count,
    MAX(timestamp) AS latest_alert_at
FROM alerts
GROUP BY severity, alert_type;
