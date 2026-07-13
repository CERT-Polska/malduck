import shutil
from datetime import datetime, timezone
from pathlib import Path


def create_snapshot(source, destination):
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")

    backup_path = Path(destination) / timestamp
    backup_path.parent.mkdir(parents=True, exist_ok=True)

    shutil.copytree(source, backup_path)

    return {
        "snapshot": str(backup_path),
        "status": "READY",
    }
