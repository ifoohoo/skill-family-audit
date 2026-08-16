"""Release-domain adapter for the shared fixed-set publisher."""

from __future__ import annotations

import importlib.util
from pathlib import Path

_SHARED_PATH = Path(__file__).resolve().parents[3] / "shared/scripts/atomic_publish.py"
if _SHARED_PATH.is_symlink() or not _SHARED_PATH.is_file():
    raise ImportError("AUDIT_SHARED_PUBLISHER_MISSING")
_SPEC = importlib.util.spec_from_file_location("_release_atomic_publish", _SHARED_PATH)
if _SPEC is None or _SPEC.loader is None:
    raise ImportError("AUDIT_SHARED_PUBLISHER_INVALID")
_SHARED = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_SHARED)

FILENAMES = frozenset({
    "release-result.json", "gate-findings.json", "evidence-list.json",
    "blocking-reasons.json",
})


class ReleasePublishError(Exception):
    """The release artifact set could not be published atomically."""


def publish_artifacts(*, output_dir: str, artifact_bytes: dict[str, bytes]) -> None:
    try:
        _SHARED.publish_fixed_artifact_set(
            output_dir=output_dir,
            artifact_bytes=artifact_bytes,
            filenames=FILENAMES,
            publisher_id="release-audit",
        )
    except _SHARED.AtomicPublishError as exc:
        raise ReleasePublishError(str(exc)) from exc


__all__ = ["FILENAMES", "ReleasePublishError", "publish_artifacts"]
