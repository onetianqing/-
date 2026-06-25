from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from graders.audit_grader import grade_audit
from runners.config_loader import load_yaml
from runners.model_client import ModelClientError, call_model


def main() -> int:
    args = parse_args()
    if args.list_models:
        print_models(load_yaml(PROJECT_ROOT / "config" / "models.yaml"))
        return 0
    if args.list_tasks:
        print_tasks(discover_tasks(args.category, "all", None, args.source_type))
        return 0

    run_id = args.run_id or datetime.now().strftime("%Y%m%d-%H%M%S")
    models = select_models(load_yaml(PROJECT_ROOT / "config" / "models.yaml"), args.models)
    tasks = discover_tasks(args.category, args.tasks, args.max_tasks, args.source_type)
    if not models:
        print("No models selected. Check --models and config/models.yaml.", file=sys.stderr)
        return 2
    if not tasks:
        print("No tasks selected.", file=sys.stderr)
        return 2

    print(f"Run ID: {run_id}")
    print(f"Models: {', '.join(model['name'] for model in models)}")
    print(f"Tasks: {', '.join(task['metadata']['id'] for task in tasks)}")

    scored_path = PROJECT_ROOT / "results" / "scored" / f"{run_id}.jsonl"
    scored_path.parent.mkdir(parents=True, exist_ok=True)
    result_rows: list[dict[str, Any]] = []

    for repetition in range(1, args.repetitions + 1):
        for model in models:
            for task in tasks:
                row = run_one(run_id, model, task, args, repetition)
                result_rows.append(row)
                with scored_path.open("a", encoding="utf-8") as handle:
                    handle.write(json.dumps(row, ensure_ascii=False) + "\n")
                print(
                    f"[rep {repetition}/{args.repetitions}] [{row['model']}] {row['task_id']}: "
                    f"score={row['score']} success={row['success']} latency_ms={row['latency_ms']}"
                )

    print_summary(result_rows)
    print(f"Scored JSONL: {scored_path}")
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run security model evaluation tasks.")
    parser.add_argument("--models", default="all", help="Comma-separated model names, or all enabled models.")
    parser.add_argument("--tasks", default="all", help="Comma-separated task IDs, or all tasks in category.")
    parser.add_argument("--category", default="audit", help="Task category to run. First version supports audit.")
    parser.add_argument("--mode", default="single_turn", choices=["single_turn"], help="Evaluation mode.")
    parser.add_argument("--temperature", type=float, default=None, help="Override model temperature.")
    parser.add_argument("--max-tokens", type=int, default=None, help="Override max output tokens.")
    parser.add_argument("--max-tasks", type=int, default=None, help="Limit number of tasks.")
    parser.add_argument("--source-type", default=None, help="Comma-separated source.type filters from task metadata.")
    parser.add_argument("--run-id", default=None, help="Custom run id.")
    parser.add_argument("--dry-run", action="store_true", help="Build prompts but do not call models.")
    parser.add_argument("--repetitions", type=int, default=1, help="Repeat each model-task pair N times.")
    parser.add_argument("--list-models", action="store_true", help="List configured models and exit.")
    parser.add_argument("--list-tasks", action="store_true", help="List discovered tasks and exit.")
    return parser.parse_args()


def select_models(config: dict[str, Any], selector: str) -> list[dict[str, Any]]:
    configured = config.get("models", [])
    if selector == "all":
        return [model for model in configured if model.get("enabled", True)]
    requested = {name.strip() for name in selector.split(",") if name.strip()}
    return [model for model in configured if model.get("name") in requested]


def discover_tasks(
    category: str,
    selector: str,
    max_tasks: int | None,
    source_type_filter: str | None = None,
) -> list[dict[str, Any]]:
    if category != "audit":
        raise SystemExit("First version supports only --category audit.")
    task_root = PROJECT_ROOT / "tasks" / category
    requested = None if selector == "all" else {item.strip() for item in selector.split(",") if item.strip()}
    source_types = None
    if source_type_filter:
        source_types = {item.strip() for item in source_type_filter.split(",") if item.strip()}
    tasks: list[dict[str, Any]] = []
    for metadata_path in sorted(task_root.glob("*/metadata.json")):
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        if requested and metadata.get("id") not in requested:
            continue
        if source_types and metadata.get("source", {}).get("type") not in source_types:
            continue
        tasks.append({"metadata": metadata, "path": metadata_path.parent})
        if max_tasks is not None and len(tasks) >= max_tasks:
            break
    return tasks


def run_one(
    run_id: str,
    model: dict[str, Any],
    task: dict[str, Any],
    args: argparse.Namespace,
    repetition: int,
) -> dict[str, Any]:
    metadata = task["metadata"]
    task_path = task["path"]
    messages = build_messages(task_path, metadata)
    started = time.perf_counter()
    error = None

    if args.dry_run:
        final_answer = json.dumps({"findings": [], "summary": "dry run"}, ensure_ascii=False)
        raw_response = {
            "model": model.get("name"),
            "provider": model.get("provider"),
            "messages": messages,
            "final_answer": final_answer,
            "tool_calls": [],
            "usage": {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0},
            "latency_ms": 0,
            "cost_usd": 0.0,
            "error": None,
        }
    else:
        try:
            response = call_model(
                model,
                messages,
                temperature=args.temperature,
                max_tokens=args.max_tokens,
                response_format={"type": "json_object"},
            )
            raw_response = response.to_dict()
            final_answer = response.final_answer
        except ModelClientError as exc:
            error = str(exc)
            final_answer = ""
            raw_response = {
                "model": model.get("name"),
                "provider": model.get("provider"),
                "messages": messages,
                "final_answer": "",
                "tool_calls": [],
                "usage": {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0},
                "latency_ms": int((time.perf_counter() - started) * 1000),
                "cost_usd": 0.0,
                "error": error,
            }

    raw_path = save_raw(run_id, str(model.get("name")), str(metadata.get("id")), raw_response)
    grade = grade_audit(metadata, final_answer) if not error else None
    now = datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")
    row = {
        "run_id": run_id,
        "task_id": metadata.get("id"),
        "task_title": metadata.get("title"),
        "category": metadata.get("category"),
        "sub_category": metadata.get("sub_category"),
        "difficulty": metadata.get("difficulty"),
        "language": metadata.get("language"),
        "tags": metadata.get("tags", []),
        "task_origin": metadata.get("source", {}).get("origin"),
        "task_source_type": metadata.get("source", {}).get("type"),
        "task_source_license": metadata.get("source", {}).get("license"),
        "task_reference_url": metadata.get("source", {}).get("reference_url"),
        "expected_vuln_types": [
            vuln.get("type", "unknown")
            for vuln in metadata.get("expected", {}).get("vulnerabilities", [])
        ],
        "model": model.get("name"),
        "provider": model.get("provider"),
        "mode": args.mode,
        "repetition": repetition,
        "temperature": args.temperature if args.temperature is not None else model.get("temperature"),
        "max_turns": metadata.get("execution", {}).get("max_turns", 1),
        "success": bool(grade.success) if grade else False,
        "score": int(grade.score) if grade else 0,
        "grader": grade.grader if grade else "not_graded",
        "grade_details": grade.details if grade else {"error": error},
        "latency_ms": raw_response.get("latency_ms", 0),
        "usage": raw_response.get("usage", {}),
        "cost_usd": raw_response.get("cost_usd", 0.0),
        "final_answer_path": str(raw_path.relative_to(PROJECT_ROOT)),
        "tool_log_path": None,
        "error": error,
        "created_at": now,
    }
    return row


def build_messages(task_path: Path, metadata: dict[str, Any]) -> list[dict[str, str]]:
    system_prompt = (PROJECT_ROOT / "prompts" / "system_security_eval.txt").read_text(encoding="utf-8")
    audit_prompt = (PROJECT_ROOT / "prompts" / "audit_prompt.txt").read_text(encoding="utf-8")
    schema = (PROJECT_ROOT / "prompts" / "json_output_schema.txt").read_text(encoding="utf-8")
    task_prompt = (task_path / metadata["prompt_file"]).read_text(encoding="utf-8")
    file_blocks = []
    for relative in metadata.get("files", []):
        file_path = task_path / relative
        content = file_path.read_text(encoding="utf-8")
        file_blocks.append(f"## File: {relative}\n```text\n{content}\n```")
    user_content = "\n\n".join(
        [
            audit_prompt,
            "Please follow this JSON structure:",
            schema,
            task_prompt,
            "\n\n".join(file_blocks),
        ]
    )
    return [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_content},
    ]


def save_raw(run_id: str, model_name: str, task_id: str, raw_response: dict[str, Any]) -> Path:
    raw_dir = PROJECT_ROOT / "results" / "raw" / run_id / model_name
    raw_dir.mkdir(parents=True, exist_ok=True)
    raw_path = raw_dir / f"{task_id}.json"
    raw_path.write_text(json.dumps(raw_response, ensure_ascii=False, indent=2), encoding="utf-8")
    return raw_path


def print_summary(rows: list[dict[str, Any]]) -> None:
    if not rows:
        return
    avg = sum(float(row["score"]) for row in rows) / len(rows)
    success_rate = sum(1 for row in rows if row["success"]) / len(rows)
    print(f"Average score: {avg:.1f}")
    print(f"Success rate: {success_rate:.1%}")


def print_models(config: dict[str, Any]) -> None:
    print("Configured models:")
    for model in config.get("models", []):
        enabled = "enabled" if model.get("enabled", True) else "disabled"
        print(f"- {model.get('name')} ({model.get('provider')}, {model.get('model_id')}, {enabled})")


def print_tasks(tasks: list[dict[str, Any]]) -> None:
    print("Discovered tasks:")
    for task in tasks:
        metadata = task["metadata"]
        print(
            f"- {metadata.get('id')} [{metadata.get('difficulty')}] "
            f"{metadata.get('title')} source={metadata.get('source', {}).get('type', 'unknown')} "
            f"tags={','.join(metadata.get('tags', []))}"
        )


if __name__ == "__main__":
    raise SystemExit(main())
