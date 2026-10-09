from datetime import datetime, timezone

from phase1.pipeline import Pipeline
from shared.security.audit import AuditLog
from .models import SecureEnvelope
from .security import canonical


class PermanentDeliveryError(Exception):
    pass


class SecurePipeline(Pipeline):
    def __init__(self, role, state, audit: AuditLog, capacity=100, log_directory=None):
        super().__init__(role, capacity=capacity, log_directory=log_directory)
        self.state, self.audit = state, audit
        for row in state.pending():
            self.admit(SecureEnvelope.model_validate_json(row["body"]), datetime.fromisoformat(row["arrival"]))

    @staticmethod
    def body(message):
        return canonical(message.model_dump(mode="json"))

    async def transmit_next(self, sender):
        try:
            return await super().transmit_next(sender)
        except PermanentDeliveryError as exc:
            item = self.in_flight
            self.audit.append("delivery", "REJECTED", str(exc), item.message.message_id,
                              item.message.device_id)
            self.state.complete(item.message.message_id, "rejected")
            self.state.increment("terminal_delivery_rejections")
            self.record(item, "delivery_rejected", datetime.now(timezone.utc), reason=str(exc))
            self.accepted_ids.pop(str(item.message.message_id))
            self.in_flight = None
            return True

    def record(self, item, event, transmission=None, queue_length=None, reason=""):
        super().record(item, event, transmission, queue_length, reason)
        if event == "transmitted":
            self.audit.append("delivery", "TRANSMITTED", message_id=item.message.message_id,
                              device_id=item.message.device_id)
            self.state.complete(item.message.message_id, "transmitted")
            self.state.increment("transmitted_messages")
