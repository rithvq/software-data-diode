"""Preserve legacy runtime files while isolating service volume mounts."""
from pathlib import Path
import shutil


def initialize(root: Path):
    root = root.resolve()
    for service in ("edge-gateway", "data-diode", "fog-receiver"):
        directory = root / service
        if directory.is_symlink():
            raise ValueError("runtime directory must not be a symlink")
        directory.mkdir(exist_ok=True)
        names = [f"{service}-audit.jsonl"]
        if service == "edge-gateway":
            names.append("edge-gateway-sequences.json")
        for name in names:
            source, target = root / name, directory / name
            if source.is_symlink() or target.is_symlink():
                raise ValueError("runtime state must not be a symlink")
            if source.is_file() and not target.exists():
                temporary = target.with_suffix(target.suffix + ".migrating")
                if temporary.is_symlink():
                    raise ValueError("migration temporary file must not be a symlink")
                shutil.copyfile(source, temporary)
                temporary.replace(target)
    print("Service runtime directories ready; existing state preserved")


if __name__ == "__main__":
    initialize(Path("/logs"))
