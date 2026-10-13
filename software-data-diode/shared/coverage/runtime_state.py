"""Explicit local provisioning of a separate, non-root Edge ledger directory."""
import argparse
from pathlib import Path

from .contracts import load_contract
from .ledger import ObservationLedger, PROJECT_NAME


def initialize(directory: Path, contract_path: Path, project_name: str):
    if project_name != PROJECT_NAME or directory.is_symlink():
        raise ValueError("separate research project and nonsymlink directory required")
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "observations.sqlite3"
    with_ledger = ObservationLedger(path, load_contract(contract_path),
                                   project_name=project_name, create=not path.exists())
    try:
        return with_ledger.status()
    finally:
        with_ledger.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--project-name", choices=[PROJECT_NAME], required=True)
    arguments = parser.parse_args()
    result = initialize(arguments.directory, arguments.contract, arguments.project_name)
    print("Research ledger provisioned; epoch=" + result["epoch"])
