from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from runners.benchmark import benchmark_fields


INDEX_RELATIVE_PATH = Path("tasks") / "task_index.json"


def index_path(project_root: Path) -> Path:
    return project_root / INDEX_RELATIVE_PATH


def build_task_index(project_root: Path) -> dict[str, Any]:
    entries = [entry for entry in scan_task_entries(project_root)]
    categories: dict[str, int] = {}
    for entry in entries:
        category = str(entry.get("category") or "unknown")
        categories[category] = categories.get(category, 0) + 1
    return {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "task_count": len(entries),
        "categories": dict(sorted(categories.items())),
        "tasks": entries,
    }


def write_task_index(project_root: Path, output_path: Path | None = None) -> Path:
    path = output_path or index_path(project_root)
    index = build_task_index(project_root)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(index, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return path


def load_task_entries(project_root: Path, category: str | None = None, prefer_index: bool = True) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]]
    if prefer_index and index_path(project_root).exists():
        try:
            index = json.loads(index_path(project_root).read_text(encoding="utf-8"))
            entries = [entry for entry in index.get("tasks", []) if isinstance(entry, dict)]
        except (OSError, json.JSONDecodeError):
            entries = list(scan_task_entries(project_root))
    else:
        entries = list(scan_task_entries(project_root))

    if category:
        entries = [entry for entry in entries if entry.get("category") == category]
    return sorted(entries, key=lambda item: str(item.get("id") or ""))


def load_task_metadata_map(project_root: Path, prefer_index: bool = True) -> dict[str, dict[str, Any]]:
    metadata: dict[str, dict[str, Any]] = {}
    for entry in load_task_entries(project_root, prefer_index=prefer_index):
        item = entry.get("metadata")
        if isinstance(item, dict) and item.get("id"):
            metadata[str(item.get("id"))] = item
    return metadata


def task_index_status(project_root: Path) -> dict[str, Any]:
    path = index_path(project_root)
    if not path.exists():
        return {
            "exists": False,
            "path": str(path.relative_to(project_root)),
            "task_count": 0,
            "categories": {},
            "generated_at": "",
        }
    try:
        index = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {
            "exists": True,
            "path": str(path.relative_to(project_root)),
            "error": str(exc),
            "task_count": 0,
            "categories": {},
            "generated_at": "",
        }
    return {
        "exists": True,
        "path": str(path.relative_to(project_root)),
        "task_count": int(index.get("task_count") or 0),
        "categories": index.get("categories", {}),
        "generated_at": str(index.get("generated_at") or ""),
        "schema_version": index.get("schema_version"),
    }


def scan_task_entries(project_root: Path) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for metadata_path in sorted((project_root / "tasks").glob("*/*/metadata.json")):
        try:
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        entries.append(task_entry_from_metadata(project_root, metadata_path, metadata))
    return entries


def task_entry_from_metadata(project_root: Path, metadata_path: Path, metadata: dict[str, Any]) -> dict[str, Any]:
    source = metadata.get("source", {}) if isinstance(metadata.get("source"), dict) else {}
    benchmark = benchmark_fields(metadata)
    task_dir = metadata_path.parent
    return {
        "id": metadata.get("id"),
        "title": metadata.get("title"),
        "category": metadata.get("category"),
        "sub_category": metadata.get("sub_category"),
        "difficulty": metadata.get("difficulty"),
        "language": metadata.get("language"),
        "tags": metadata.get("tags", []),
        "source_type": source.get("type", "unknown"),
        "origin": source.get("origin", "unknown"),
        "license": source.get("license", "unknown"),
        "reference_url": source.get("reference_url", ""),
        "benchmark_suite": benchmark["benchmark_suite"],
        "benchmark_included": benchmark["benchmark_included"],
        "benchmark_capability": benchmark["benchmark_capability"],
        "benchmark_weight": benchmark["benchmark_weight"],
        "difficulty_weight": benchmark["difficulty_weight"],
        "effective_weight": benchmark["effective_weight"],
        "leakage_risk": benchmark["leakage_risk"],
        "task_dir": str(task_dir.relative_to(project_root)).replace("\\", "/"),
        "metadata_path": str(metadata_path.relative_to(project_root)).replace("\\", "/"),
        "metadata": metadata,
    }


def public_task_record(entry: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in entry.items()
        if key not in {"metadata", "metadata_path", "task_dir"}
    }
