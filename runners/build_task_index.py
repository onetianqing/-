from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from runners.task_index import build_task_index, write_task_index


def main() -> int:
    args = parse_args()
    if args.check:
        current = build_task_index(PROJECT_ROOT)
        output_path = PROJECT_ROOT / args.output
        if not output_path.exists():
            print(json.dumps({"ok": False, "reason": "task_index_missing", "path": args.output}, ensure_ascii=False))
            return 1
        try:
            existing = json.loads(output_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            print(json.dumps({"ok": False, "reason": "invalid_json", "error": str(exc)}, ensure_ascii=False))
            return 1
        ok = existing.get("task_count") == current.get("task_count") and existing.get("categories") == current.get("categories")
        print(json.dumps({"ok": ok, "task_count": current.get("task_count"), "categories": current.get("categories")}, ensure_ascii=False))
        return 0 if ok else 1

    path = write_task_index(PROJECT_ROOT, PROJECT_ROOT / args.output)
    index = json.loads(path.read_text(encoding="utf-8"))
    print(f"Task index written: {path}")
    print(f"Tasks: {index.get('task_count')} categories={index.get('categories')}")
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build the task metadata index used by runner, UI and reports.")
    parser.add_argument("--output", default="tasks/task_index.json", help="Index output path relative to project root.")
    parser.add_argument("--check", action="store_true", help="Check whether the current index has the same task count/category summary.")
    return parser.parse_args()


if __name__ == "__main__":
    raise SystemExit(main())
