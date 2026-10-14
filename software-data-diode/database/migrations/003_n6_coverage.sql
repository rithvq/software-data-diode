BEGIN;

-- Epoch bindings and watermarks are tombstones, not an expiring replay cache.
CREATE TABLE IF NOT EXISTS coverage_epochs (
    gateway_id TEXT NOT NULL, ledger_epoch TEXT NOT NULL, binding JSONB NOT NULL,
    retired BOOLEAN NOT NULL DEFAULT FALSE, PRIMARY KEY (gateway_id, ledger_epoch)
);
CREATE TABLE IF NOT EXISTS coverage_heads (
    gateway_id TEXT NOT NULL, ledger_epoch TEXT NOT NULL, device_id TEXT NOT NULL,
    high_window BIGINT NOT NULL, PRIMARY KEY (gateway_id, ledger_epoch, device_id),
    FOREIGN KEY (gateway_id, ledger_epoch) REFERENCES coverage_epochs
);
CREATE TABLE IF NOT EXISTS coverage_scopes (
    scope_id CHAR(64) PRIMARY KEY, gateway_id TEXT NOT NULL, ledger_epoch TEXT NOT NULL,
    contract_hash CHAR(64) NOT NULL, device_id TEXT NOT NULL, window_index BIGINT NOT NULL,
    quarantined BOOLEAN NOT NULL DEFAULT FALSE,
    UNIQUE (gateway_id, ledger_epoch, contract_hash, device_id, window_index),
    FOREIGN KEY (gateway_id, ledger_epoch) REFERENCES coverage_epochs
);
CREATE TABLE IF NOT EXISTS coverage_capsules (
    artifact_digest CHAR(64) PRIMARY KEY, scope_id CHAR(64) NOT NULL REFERENCES coverage_scopes,
    encoded BYTEA NOT NULL CHECK (octet_length(encoded) BETWEEN 1 AND 32768),
    body JSONB NOT NULL, verification JSONB NOT NULL,
    received_at_us BIGINT NOT NULL, persisted_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_coverage_scope ON coverage_capsules (scope_id);
CREATE TABLE IF NOT EXISTS coverage_parts (
    artifact_digest CHAR(64) NOT NULL REFERENCES coverage_capsules,
    part_index INTEGER NOT NULL CHECK (part_index BETWEEN 0 AND 95),
    encoded BYTEA NOT NULL CHECK (octet_length(encoded) BETWEEN 1 AND 1200),
    PRIMARY KEY (artifact_digest, part_index)
);
CREATE TABLE IF NOT EXISTS coverage_facts (
    artifact_digest CHAR(64) NOT NULL REFERENCES coverage_capsules,
    condition_id TEXT NOT NULL, facts JSONB NOT NULL,
    PRIMARY KEY (artifact_digest, condition_id)
);
CREATE TABLE IF NOT EXISTS coverage_outcomes (
    outcome_id CHAR(64) PRIMARY KEY, timestamp_us BIGINT NOT NULL,
    reason_code TEXT NOT NULL, artifact_digest CHAR(64), details JSONB NOT NULL
);
CREATE TABLE IF NOT EXISTS coverage_conflicts (
    scope_id CHAR(64) NOT NULL REFERENCES coverage_scopes,
    first_digest CHAR(64) NOT NULL REFERENCES coverage_capsules,
    second_digest CHAR(64) NOT NULL REFERENCES coverage_capsules,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (scope_id, first_digest, second_digest)
);
-- N7 will consume these publications and produce verdicts. No rule evaluation
-- or alert is implied by the N6 verification transaction.
CREATE TABLE IF NOT EXISTS coverage_publications (
    scope_id CHAR(64) PRIMARY KEY REFERENCES coverage_scopes,
    revision BIGINT NOT NULL DEFAULT 1, published_revision BIGINT NOT NULL DEFAULT 0,
    CHECK (published_revision <= revision)
);
CREATE TABLE IF NOT EXISTS coverage_rule_verdicts (
    gateway_id TEXT NOT NULL, ledger_epoch TEXT NOT NULL, contract_hash CHAR(64) NOT NULL,
    window_index BIGINT NOT NULL, rule_id TEXT NOT NULL,
    verdict TEXT NOT NULL CHECK (verdict IN ('TRUE', 'FALSE', 'UNKNOWN')),
    verification_status TEXT NOT NULL, evidence JSONB NOT NULL, reasons JSONB NOT NULL,
    verifier_version TEXT NOT NULL, PRIMARY KEY (gateway_id, ledger_epoch, contract_hash, window_index, rule_id)
);
CREATE TABLE IF NOT EXISTS coverage_performance (
    artifact_digest CHAR(64) PRIMARY KEY REFERENCES coverage_capsules,
    verification_seconds DOUBLE PRECISION NOT NULL CHECK (verification_seconds >= 0),
    transport_bytes BIGINT NOT NULL CHECK (transport_bytes >= 0),
    database_commit_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE OR REPLACE VIEW usable_coverage_facts AS
SELECT s.scope_id, s.gateway_id, s.ledger_epoch, s.contract_hash, s.device_id,
       s.window_index, f.condition_id, f.facts, c.verification
FROM coverage_scopes s JOIN coverage_capsules c USING (scope_id)
JOIN coverage_facts f USING (artifact_digest)
JOIN coverage_epochs e ON (e.gateway_id=s.gateway_id AND e.ledger_epoch=s.ledger_epoch)
WHERE NOT s.quarantined AND NOT e.retired
  AND c.verification->>'status' = 'VALID';

COMMIT;
