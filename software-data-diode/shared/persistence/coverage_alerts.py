"""Lightweight Alert Engine transaction; no cryptography or Edge imports."""
import json

from shared.models import AlertRecord


def deliver_alert(repository, delivery):
    with repository._connect() as connection, connection.cursor() as cursor:
        cursor.execute("""SELECT v.gateway_id,v.ledger_epoch FROM coverage_alert_intents i
            JOIN coverage_rule_verdicts v USING(decision_id) WHERE i.alert_id=%s""", (delivery.alert_id,))
        scope = cursor.fetchone()
        if scope is None:
            return "UNKNOWN_IDENTITY"
        cursor.execute("SELECT retired FROM coverage_epochs WHERE gateway_id=%s AND ledger_epoch=%s FOR UPDATE", scope)
        retired = cursor.fetchone()[0]
        cursor.execute("SELECT decision_id,delivery_revision,delivered_revision,active,payload,reason,kind FROM coverage_alert_intents WHERE alert_id=%s FOR UPDATE", (delivery.alert_id,))
        decision, revision, delivered, active, payload, reason, kind = cursor.fetchone()
        if revision != delivery.revision:
            return "SUPERSEDED"
        if delivered >= revision:
            return "DUPLICATE"
        cursor.execute("SELECT verdict FROM coverage_rule_verdicts WHERE decision_id=%s", (decision,))
        truth = cursor.fetchone()[0]
        if kind == "INCIDENT" and (retired or truth != "TRUE"):
            active, reason = False,"DECISION_REASSESSED"
        if active:
            alert = AlertRecord.model_validate(payload)
            cursor.execute("""INSERT INTO alerts (alert_id,timestamp,source_devices,alert_type,severity,evidence,description)
                VALUES (%s,%s,%s,%s,%s,%s::jsonb,%s) ON CONFLICT (alert_id) DO NOTHING""",
                (alert.alert_id,alert.timestamp,alert.source_devices,alert.alert_type,str(alert.severity),json.dumps(alert.evidence),alert.description))
        state = {"decision_id":str(decision),"revision":revision,"active":active,"reason":reason,"payload":payload}
        cursor.execute("INSERT INTO coverage_alert_states VALUES (%s,%s,%s,%s,%s) ON CONFLICT (alert_id) DO UPDATE SET revision=excluded.revision,active=excluded.active,reason=excluded.reason", (delivery.alert_id,decision,revision,active,reason))
        cursor.execute("INSERT INTO coverage_alert_history VALUES (%s,%s,%s::jsonb) ON CONFLICT DO NOTHING", (delivery.alert_id,revision,json.dumps(state)))
        cursor.execute("UPDATE coverage_alert_intents SET delivered_revision=%s WHERE alert_id=%s", (revision,delivery.alert_id))
        return "STORED" if active else "INACTIVE"
