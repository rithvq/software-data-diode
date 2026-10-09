"""Container-local isolation probes; only targets supplied by the Docker verifier."""

import json
import socket
import sys
import urllib.error
import urllib.request


def main():
    config = json.load(sys.stdin)
    results = []
    for name in ("edge-device", "edge-gateway"):
        try:
            addresses = socket.getaddrinfo(name, 8000, type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            results.append({"check": f"DNS {name}", "passed": True, "detail": str(exc)})
        else:
            results.append({"check": f"DNS {name}", "passed": False, "detail": str(addresses)})
    for target in config["targets"]:
        try:
            with socket.create_connection((target["ip"], 8000), timeout=1):
                pass
        except OSError as exc:
            results.append({"check": f"TCP {target['service']} {target['ip']}:8000",
                            "passed": True, "detail": str(exc)})
        else:
            results.append({"check": f"TCP {target['service']} {target['ip']}:8000",
                            "passed": False, "detail": "unexpected connection"})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    request = urllib.request.Request("http://unidirectional-gateway:8000/ingest", data=b"{}",
                                     headers={"Content-Type": "application/json"})
    try:
        with opener.open(request, timeout=5) as response:
            status = response.status
    except urllib.error.HTTPError as exc:
        status = exc.code
    except OSError as exc:
        results.append({"check": "Reverse ingress guard", "passed": False, "detail": str(exc)})
    else:
        results.append({"check": "Reverse ingress guard", "passed": False, "detail": f"HTTP {status}"})
    if 'status' in locals() and status >= 400:
        results.append({"check": "Reverse ingress guard", "passed": status == 403,
                        "detail": f"HTTP {status}; expected 403 from reachable gateway"})
    print(json.dumps(results))


if __name__ == "__main__":
    main()
