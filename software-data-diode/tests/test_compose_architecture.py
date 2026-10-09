from pathlib import Path

import yaml


def test_compose_defines_five_typed_edge_nodes_and_isolated_fog() -> None:
    compose_path = Path(__file__).resolve().parents[1] / "docker-compose.yml"
    compose = yaml.safe_load(compose_path.read_text(encoding="utf-8"))
    services = compose["services"]

    expected_types = {
        "edge-device-01": "environmental",
        "edge-device-02": "system",
        "edge-device-03": "network",
        "edge-device-04": "security",
        "edge-device-05": "industrial",
    }
    for service_name, telemetry_type in expected_types.items():
        assert services[service_name]["environment"]["DEVICE_TYPE"] == telemetry_type
        assert services[service_name]["networks"] == ["edge-network"]

    assert set(services["data-diode"]["networks"]) == {
        "diode-network",
        "fog-ingress-network",
    }
    assert set(services["fog-receiver"]["networks"]) == {
        "fog-ingress-network",
        "fog-services-network",
    }
    assert services["postgres"]["networks"] == ["fog-services-network"]
    assert "fog-services-network" not in services["data-diode"]["networks"]
