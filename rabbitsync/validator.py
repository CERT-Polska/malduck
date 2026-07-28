import json
from pathlib import Path


def validate_release_manifest(path="approved/releases/release.json"):
    release_path = Path(path)
    if not release_path.exists():
        raise FileNotFoundError(f"Release manifest not found: {release_path}")

    data = json.loads(release_path.read_text())
    if data.get("system") != "WEAREONE10BILLION":
        raise ValueError("Unexpected system identifier in release manifest")
    if data.get("status") != "APPROVED":
        raise ValueError("Release manifest is not approved")

    return data


if __name__ == "__main__":
    payload = validate_release_manifest()
    print(json.dumps(payload, indent=2))
