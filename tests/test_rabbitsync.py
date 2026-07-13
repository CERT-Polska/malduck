import json
from pathlib import Path

import pytest

from rabbitsync.backup import create_snapshot
from rabbitsync.report import generate_report
from rabbitsync.sync import sync_release
from rabbitsync.validator import validate_release_manifest


def test_create_snapshot_copies_directory(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "release.txt").write_text("ready")
    destination = tmp_path / "backups"
    destination.mkdir()

    result = create_snapshot(source, destination)
    backup_path = Path(result["snapshot"])

    assert backup_path.exists()
    assert (backup_path / "release.txt").read_text() == "ready"
    assert result["status"] == "READY"


def test_sync_release_returns_expected_payload():
    result = sync_release()

    assert result == {
        "system": "WEAREONE10BILLION",
        "source": "GitHub",
        "destination": "Dropbox",
        "status": "SUCCESS",
    }


def test_validate_release_manifest_accepts_approved_release():
    payload = validate_release_manifest("approved/releases/release.json")

    assert payload["status"] == "APPROVED"
    assert payload["system"] == "WEAREONE10BILLION"


def test_validate_release_manifest_rejects_missing_file(tmp_path):
    missing_manifest = tmp_path / "missing.json"

    with pytest.raises(FileNotFoundError):
        validate_release_manifest(str(missing_manifest))


def test_validate_release_manifest_rejects_unapproved_status(tmp_path):
    manifest = tmp_path / "release.json"
    manifest.write_text(json.dumps({"system": "WEAREONE10BILLION", "status": "PENDING"}))

    with pytest.raises(ValueError):
        validate_release_manifest(str(manifest))


def test_generate_report_creates_json_report(tmp_path):
    report_path = tmp_path / "validation-report.json"

    result = generate_report(str(report_path))

    assert result["status"] == "READY"
    assert json.loads(report_path.read_text())["status"] == "APPROVED"
