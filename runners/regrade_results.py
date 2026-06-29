from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from graders.audit_grader import diagnose_audit_answer, grade_audit
from graders.ctf_grader import diagnose_ctf_answer, grade_ctf
from graders.log_grader import diagnose_log_answer, grade_log_analysis
from graders.patch_grader import diagnose_patch_answer, grade_patch
from graders.tool_use_grader import diagnose_tool_use_answer, grade_tool_use
from runners.task_index import load_task_metadata_map


def main() -> int:
    args = parse_args()
    input_path = PROJECT_ROOT / "results" / "scored" / f"{args.run_id}.jsonl"
    if not input_path.exists():
        print(f"Scored file not found: {input_path}", file=sys.stderr)
        return 2

    output_id = args.output_id or f"{args.run_id}-regraded"
    output_path = PROJECT_ROOT / "results" / "scored" / f"{output_id}.jsonl"
    output_path.parent.mkdir(parents=True, exist_ok=True)

    task_metadata = load_task_metadata()
    rows = [json.loads(line) for line in input_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    regraded = [regrade_row(row, task_metadata) for row in rows]
    with output_path.open("w", encoding="utf-8") as handle:
        for row in regraded:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")

    print(f"Regraded rows: {len(regraded)}")
    print(f"Output JSONL: {output_path}")
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Regrade an existing run without calling model APIs.")
    parser.add_argument("--run-id", required=True, help="Existing run id in results/scored.")
    parser.add_argument("--output-id", default=None, help="New scored output id. Default: <run-id>-regraded.")
    return parser.parse_args()


def load_task_metadata() -> dict[str, dict[str, Any]]:
    return load_task_metadata_map(PROJECT_ROOT)


def regrade_row(row: dict[str, Any], task_metadata: dict[str, dict[str, Any]]) -> dict[str, Any]:
    updated = dict(row)
    task_id = str(row.get("task_id") or "")
    metadata = task_metadata.get(task_id)
    if not metadata:
        updated["regrade_error"] = f"Task metadata not found: {task_id}"
        return updated

    final_answer = load_final_answer(row)
    if final_answer is None:
        updated["regrade_error"] = f"Raw answer not found: {row.get('final_answer_path')}"
        return updated

    grade = grade_task(metadata, final_answer)
    diagnosis = diagnose_answer(metadata, final_answer)
    updated["category"] = metadata.get("category", updated.get("category"))
    updated["success"] = bool(grade.success)
    updated["score"] = int(grade.score)
    updated["grader"] = grade.grader
    updated["grade_details"] = grade.details
    updated["answer_diagnosis"] = diagnosis
    updated["regraded_at"] = datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")
    return updated


def load_final_answer(row: dict[str, Any]) -> str | None:
    relative = row.get("final_answer_path")
    if not relative:
        return None
    raw_path = PROJECT_ROOT / str(relative)
    if not raw_path.exists():
        raw_path = PROJECT_ROOT / str(relative).replace("\\", "/")
    if not raw_path.exists():
        return None
    data = json.loads(raw_path.read_text(encoding="utf-8"))
    return str(data.get("final_answer") or "")


def grade_task(metadata: dict[str, Any], final_answer: str):
    category = metadata.get("category")
    if category == "log_analysis":
        return grade_log_analysis(metadata, final_answer)
    if category == "patch":
        return grade_patch(metadata, final_answer)
    if category == "ctf":
        return grade_ctf(metadata, final_answer)
    if category == "tool_use":
        return grade_tool_use(metadata, final_answer)
    return grade_audit(metadata, final_answer)


def diagnose_answer(metadata: dict[str, Any], final_answer: str) -> dict[str, Any]:
    category = metadata.get("category")
    if category == "log_analysis":
        return diagnose_log_answer(metadata, final_answer)
    if category == "patch":
        return diagnose_patch_answer(metadata, final_answer)
    if category == "ctf":
        return diagnose_ctf_answer(metadata, final_answer)
    if category == "tool_use":
        return diagnose_tool_use_answer(metadata, final_answer)
    return diagnose_audit_answer(metadata, final_answer)


if __name__ == "__main__":
    raise SystemExit(main())
