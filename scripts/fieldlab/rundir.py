"""Run directory management for field-lab sessions.

Creates runs/<YYYYMMDD-HHMMSS>-fieldlab/ with subdirectories matching
the existing conwrt run convention (see docs/process.md, scripts/lib/common.sh).
"""

from __future__ import annotations

import datetime
import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
RUNS_DIR = REPO_ROOT / "runs"


def new_session_id(label: str = "fieldlab") -> str:
    """Generate a run ID matching the existing convention: YYYYMMDD-HHMMSS-slug."""
    ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    slug = label.lower().replace(" ", "-")
    return f"{ts}-{slug}"


class FieldLabRun:
    """A field-lab run directory with inspect/, captures/, discover/ subdirs."""

    def __init__(self, session_id: str, base_dir: Path | None = None) -> None:
        self.session_id = session_id
        self.base_dir = base_dir or RUNS_DIR
        self.run_dir = self.base_dir / session_id
        self.inspect_dir = self.run_dir / "inspect"
        self.captures_dir = self.run_dir / "captures"
        self.discover_dir = self.run_dir / "discover"

    @classmethod
    def create(cls, label: str = "fieldlab", base_dir: Path | None = None) -> "FieldLabRun":
        """Create a new run directory with all subdirectories and initial manifest."""
        session_id = new_session_id(label)
        run = cls(session_id, base_dir)
        run.run_dir.mkdir(parents=True, exist_ok=True)
        run.inspect_dir.mkdir(exist_ok=True)
        run.captures_dir.mkdir(exist_ok=True)
        run.discover_dir.mkdir(exist_ok=True)
        run._write_initial_manifest()
        return run

    def _write_initial_manifest(self) -> None:
        """Write the initial manifest.json."""
        manifest = {
            "session_id": self.session_id,
            "created_at": datetime.datetime.now(datetime.timezone.utc)
                .strftime("%Y-%m-%dT%H:%M:%SZ"),
            "tool": "fieldlab",
            "status": "in_progress",
            "commands_run": [],
        }
        self.manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")

    @property
    def manifest_path(self) -> Path:
        return self.run_dir / "manifest.json"

    @property
    def notes_path(self) -> Path:
        return self.run_dir / "notes.md"

    def read_manifest(self) -> dict:
        """Read and return the manifest as a dict."""
        return json.loads(self.manifest_path.read_text())

    def update_manifest(self, **updates: object) -> None:
        """Merge updates into the manifest and write back."""
        manifest = self.read_manifest()
        manifest.update(updates)
        self.manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")

    def record_command(self, command: str, **details: object) -> None:
        """Append a command record to the manifest."""
        manifest = self.read_manifest()
        entry = {"command": command, **details}
        manifest.setdefault("commands_run", []).append(entry)
        self.manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")

    def write_notes(self, content: str) -> None:
        """Write or append to notes.md."""
        if self.notes_path.exists():
            existing = self.notes_path.read_text()
            self.notes_path.write_text(existing.rstrip() + "\n\n" + content + "\n")
        else:
            self.notes_path.write_text(content + "\n")
