BEGIN;
ALTER TABLE coverage_rule_verdicts ADD COLUMN IF NOT EXISTS decision_id UUID;
ALTER TABLE coverage_rule_verdicts ADD COLUMN IF NOT EXISTS revision BIGINT NOT NULL DEFAULT 1;
ALTER TABLE coverage_rule_verdicts ADD COLUMN IF NOT EXISTS result JSONB NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE coverage_rule_verdicts ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
CREATE UNIQUE INDEX IF NOT EXISTS idx_coverage_decision ON coverage_rule_verdicts(decision_id);
CREATE TABLE IF NOT EXISTS coverage_rule_history (
    decision_id UUID NOT NULL,revision BIGINT NOT NULL,record JSONB NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),PRIMARY KEY(decision_id,revision)
);
CREATE TABLE IF NOT EXISTS coverage_alert_intents (
    alert_id UUID PRIMARY KEY,decision_id UUID NOT NULL,kind TEXT NOT NULL CHECK(kind IN ('INCIDENT','VISIBILITY')),
    delivery_revision BIGINT NOT NULL DEFAULT 1,delivered_revision BIGINT NOT NULL DEFAULT 0,
    active BOOLEAN NOT NULL, payload JSONB NOT NULL, reason TEXT NOT NULL,
    UNIQUE(decision_id,kind),CHECK(delivered_revision<=delivery_revision)
);
CREATE TABLE IF NOT EXISTS coverage_alert_states (
    alert_id UUID PRIMARY KEY REFERENCES coverage_alert_intents,decision_id UUID NOT NULL,
    revision BIGINT NOT NULL,active BOOLEAN NOT NULL,reason TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS coverage_alert_history (
    alert_id UUID NOT NULL,revision BIGINT NOT NULL,state JSONB NOT NULL,PRIMARY KEY(alert_id,revision)
);
CREATE TABLE IF NOT EXISTS coverage_alert_cooldowns (
    gateway_id TEXT,ledger_epoch TEXT,contract_hash CHAR(64),rule_id TEXT,kind TEXT,last_window BIGINT NOT NULL,
    PRIMARY KEY(gateway_id,ledger_epoch,contract_hash,rule_id,kind)
);
CREATE TABLE IF NOT EXISTS coverage_original_witnesses (
    artifact_digest CHAR(64) REFERENCES coverage_capsules,ingress_sequence BIGINT NOT NULL,
    input_hash CHAR(64) NOT NULL,ingress_utc_us BIGINT NOT NULL,canonical_input BYTEA NOT NULL,
    PRIMARY KEY(artifact_digest,ingress_sequence),CHECK(octet_length(canonical_input) BETWEEN 1 AND 65536)
);
CREATE TABLE IF NOT EXISTS coverage_monitor_state (
    gateway_id TEXT,ledger_epoch TEXT,contract_hash CHAR(64),config_digest CHAR(64) NOT NULL,
    next_window BIGINT NOT NULL,last_tick_us BIGINT NOT NULL,
    PRIMARY KEY(gateway_id,ledger_epoch,contract_hash)
);
CREATE TABLE IF NOT EXISTS coverage_monitor_gaps (
    gateway_id TEXT,ledger_epoch TEXT,contract_hash CHAR(64),first_window BIGINT,last_window BIGINT,
    reason TEXT NOT NULL,PRIMARY KEY(gateway_id,ledger_epoch,contract_hash,first_window,last_window)
);
CREATE INDEX IF NOT EXISTS idx_coverage_authenticated_expiry ON coverage_outcomes
    ((details->'authenticated_scope'->>'gateway_id'),(details->'authenticated_scope'->>'ledger_epoch'),
     (details->'authenticated_scope'->>'contract_hash'),(details->'authenticated_scope'->>'window_index'))
    WHERE reason_code IN ('EXPIRED_EVIDENCE','EXPIRED_EVIDENCE_WINDOW');
CREATE OR REPLACE FUNCTION coverage_revision_before() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.decision_id IS NULL THEN RETURN NEW; END IF;
    IF TG_OP='UPDATE' AND NEW.verifier_version='rccd-fog-verifier-v1'
       AND NEW.verification_status IN ('CONFLICT','RETIRED') THEN
        NEW.result := NEW.result || jsonb_build_object('truth','UNKNOWN','coverage_complete',false,
            'verification_status',NEW.verification_status,'reason_codes',NEW.reasons,
            'supporting_artifacts','[]'::jsonb,'artifact_verification',CASE WHEN NEW.verification_status='CONFLICT' THEN 'CONFLICT' ELSE 'INVALID' END,
            'conditions','[]'::jsonb,'condition_bounds','{}'::jsonb,'supporting_conditions','[]'::jsonb,
            'revision_cause','SCOPE_INVALIDATED_PENDING_RULE_REASSESSMENT',
            'coverage_health',jsonb_build_object('state','DEGRADED','complete',false));
    END IF;
    IF TG_OP='UPDATE' THEN
        IF ROW(NEW.verdict,NEW.verification_status,NEW.evidence,NEW.reasons,NEW.verifier_version,NEW.result)
           IS NOT DISTINCT FROM ROW(OLD.verdict,OLD.verification_status,OLD.evidence,OLD.reasons,OLD.verifier_version,OLD.result)
        THEN RETURN NULL; END IF;
        NEW.revision:=OLD.revision+1;
    END IF;
    NEW.updated_at:=NOW();
    RETURN NEW;
END $$;
CREATE OR REPLACE FUNCTION coverage_revision_after() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.decision_id IS NOT NULL THEN
        INSERT INTO coverage_rule_history VALUES(NEW.decision_id,NEW.revision,to_jsonb(NEW),NOW()) ON CONFLICT DO NOTHING;
        IF NEW.verdict!='TRUE' THEN
            UPDATE coverage_alert_intents SET active=false,reason='DECISION_REASSESSED',delivery_revision=delivery_revision+1
                WHERE decision_id=NEW.decision_id AND kind='INCIDENT' AND active;
        END IF;
    END IF;
    RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS coverage_revision_before ON coverage_rule_verdicts;
CREATE TRIGGER coverage_revision_before BEFORE INSERT OR UPDATE ON coverage_rule_verdicts FOR EACH ROW EXECUTE FUNCTION coverage_revision_before();
DROP TRIGGER IF EXISTS coverage_revision_after ON coverage_rule_verdicts;
CREATE TRIGGER coverage_revision_after AFTER INSERT OR UPDATE ON coverage_rule_verdicts FOR EACH ROW EXECUTE FUNCTION coverage_revision_after();
COMMIT;
