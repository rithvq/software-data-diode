"""Explicit local-research selection; legacy HTTP is the default."""
import os
from .ledger import PROJECT_NAME


def research_udp_enabled():
    mode = os.getenv("DIODE_FORWARD_TRANSPORT", "http").lower()
    if mode not in {"http", "udp"}:
        raise ValueError("unsupported DIODE_FORWARD_TRANSPORT")
    if mode == "udp":
        if os.getenv("COVERAGE_PROJECT_NAME") != PROJECT_NAME:
            raise ValueError("UDP requires the isolated research project")
        for key in ("COVERAGE_TRUST_PATH", "COVERAGE_CONTRACT_PATH", "COVERAGE_TRANSPORT_CONFIG"):
            if not os.getenv(key):
                raise ValueError("missing local research provisioning: "+key)
    return mode == "udp"
