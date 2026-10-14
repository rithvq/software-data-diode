BEGIN;
CREATE INDEX IF NOT EXISTS idx_coverage_window_page
    ON coverage_rule_verdicts(window_index DESC,decision_id DESC);
CREATE INDEX IF NOT EXISTS idx_coverage_filtered_page
    ON coverage_rule_verdicts(contract_hash,rule_id,window_index DESC,decision_id DESC);
CREATE INDEX IF NOT EXISTS idx_coverage_rule_devices
    ON coverage_rule_verdicts USING gin ((result->'source_devices'));
CREATE INDEX IF NOT EXISTS idx_coverage_capsule_receipt ON coverage_capsules(received_at_us DESC);
CREATE INDEX IF NOT EXISTS idx_coverage_outcome_reason ON coverage_outcomes(reason_code);
COMMIT;
