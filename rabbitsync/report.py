import json
from pathlib import Path

try:
    from .validator import validate_release_manifest
except ImportError:  # pragma: no cover - allows running as a script
    from validator import validate_release_manifest


def generate_report(path="approved/reports/validation-report.json"):
    payload = validate_release_manifest()
    report_path = Path(path)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(payload, indent=2))
    return {"path": str(report_path), "status": "READY"}


if __name__ == "__main__":
    result = generate_report()
    print(json.dumps(result, indent=2))
