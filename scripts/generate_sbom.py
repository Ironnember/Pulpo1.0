"""Generate a deterministic, unsigned SBOM from supported Python manifests."""

from __future__ import annotations

import json
from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
MANIFESTS = (ROOT / "pyproject.toml", ROOT / "authority-service/pyproject.toml", ROOT / "custody-service/pyproject.toml")


def dependencies(path: Path) -> list[str]:
    values: list[str] = []
    in_deps = False
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if re.match(r'^[A-Za-z0-9_-]+\s*=\s*\[$', stripped):
            in_deps = True
        elif in_deps and stripped == "]":
            in_deps = False
        elif in_deps and stripped.startswith('"') and stripped.endswith('",'):
            values.append(stripped[1:-2])
    return values


def main() -> int:
    values = {dependency for manifest in MANIFESTS for dependency in dependencies(manifest)}
    audit_manifest = ROOT / "requirements-audit.txt"
    if audit_manifest.exists():
        values.update(
            line.strip()
            for line in audit_manifest.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.startswith("#")
        )
    components = sorted(values)
    document = {
        "bomFormat": "pulpo-deterministic-sbom-v1",
        "components": [{"type": "library", "dependency": value} for value in components],
        "manifests": [str(path.relative_to(ROOT)).replace("\\", "/") for path in MANIFESTS],
        "signed": False,
        "signing_responsibility": "deployment-or-ci",
    }
    output = json.dumps(document, indent=2, sort_keys=True) + "\n"
    if len(sys.argv) == 2:
        Path(sys.argv[1]).write_text(output, encoding="utf-8")
    else:
        sys.stdout.write(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
