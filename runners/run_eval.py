from __future__ import annotations

import argparse
import json
import os
import random
import sys
import time
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
from runners.benchmark import benchmark_fields, benchmark_score, benchmark_solve_rate
from runners.config_loader import load_yaml
from runners.model_client import ModelClientError, call_model, estimate_cost
from runners.task_index import load_task_entries
from runners.validate import finding, has_errors, print_human, validate_models, validate_tasks


SUPPORTED_CATEGORIES = {"audit", "log_analysis", "patch", "ctf", "tool_use"}
CATEGORY_DEFAULT_MAX_TOKENS = {
    "audit": 4096,
    "log_analysis": 4096,
    "patch": 4096,
    "ctf": 4096,
    "tool_use": 4096,
}


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(line_buffering=True)
    args = parse_args()
    if args.list_models:
        print_models(load_yaml(PROJECT_ROOT / "config" / "models.yaml"))
        return 0
    if args.list_tasks:
        print_tasks(discover_tasks(args))
        return 0

    run_id = args.run_id or datetime.now().strftime("%Y%m%d-%H%M%S")
    models = select_models(load_yaml(PROJECT_ROOT / "config" / "models.yaml"), args.models)
    tasks = discover_tasks(args)
    if not models:
        print("No models selected. Check --models and config/models.yaml.", file=sys.stderr)
        return 2
    if not tasks:
        print("No tasks selected.", file=sys.stderr)
        return 2
    if args.preflight or args.plan_only:
        preflight_exit = run_preflight(args, models, tasks)
        if preflight_exit != 0:
            return preflight_exit
    if args.plan_only:
        return 0

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
    parser.add_argument("--category", default="audit", help="Task category to run: audit, log_analysis, patch, ctf or tool_use.")
    parser.add_argument("--mode", default="single_turn", choices=["single_turn"], help="Evaluation mode.")
    parser.add_argument("--temperature", type=float, default=None, help="Override model temperature.")
    parser.add_argument("--max-tokens", type=int, default=None, help="Override max output tokens. If omitted, category default is used.")
    parser.add_argument("--max-tasks", type=int, default=None, help="Limit number of tasks.")
    parser.add_argument("--sample-size", type=int, default=None, help="Randomly sample N tasks after filters. Overrides --max-tasks for task selection.")
    parser.add_argument("--sample-seed", default="2026", help="Seed for deterministic task sampling.")
    parser.add_argument("--source-type", default=None, help="Comma-separated source.type filters from task metadata.")
    parser.add_argument("--suite", default=None, help="Comma-separated benchmark.suite filters.")
    parser.add_argument("--capability", default=None, help="Comma-separated benchmark.capability filters.")
    parser.add_argument("--difficulty", default=None, help="Comma-separated difficulty filters.")
    parser.add_argument("--run-id", default=None, help="Custom run id.")
    parser.add_argument("--dry-run", action="store_true", help="Build prompts but do not call models.")
    parser.add_argument("--preflight", action="store_true", help="Validate task metadata and model config before running.")
    parser.add_argument("--preflight-strict", action="store_true", help="Treat preflight warnings as blocking failures.")
    parser.add_argument("--plan-only", action="store_true", help="Print preflight checks and run plan, then exit without writing results.")
    parser.add_argument("--repetitions", type=int, default=1, help="Repeat each model-task pair N times.")
    parser.add_argument("--list-models", action="store_true", help="List configured models and exit.")
    parser.add_argument("--list-tasks", action="store_true", help="List discovered tasks and exit.")
    return parser.parse_args()


def run_preflight(
    args: argparse.Namespace,
    selected_models: list[dict[str, Any]],
    selected_tasks: list[dict[str, Any]],
) -> int:
    findings = []
    findings.extend(validate_tasks(args.category))
    findings.extend(validate_models(api_key_check_names={str(model.get("name")) for model in selected_models}))
    findings.extend(validate_selected_models(selected_models, args.dry_run))

    blocking = has_errors(findings) or (args.preflight_strict and bool(findings))
    if findings:
        print("Preflight checks:")
        print_human(findings)
    else:
        print("Preflight checks passed.")
    if blocking:
        print("Preflight failed. Fix the reported items or rerun without --preflight.", file=sys.stderr)
        return 2
    print_run_plan(args, selected_models, selected_tasks)
    return 0


def print_run_plan(
    args: argparse.Namespace,
    selected_models: list[dict[str, Any]],
    selected_tasks: list[dict[str, Any]],
) -> None:
    task_count = len(selected_tasks)
    model_count = len(selected_models)
    repetitions = max(1, int(args.repetitions or 1))
    call_count = task_count * model_count * repetitions
    input_tokens_by_task = {
        str(task["metadata"].get("id")): estimate_messages_tokens(build_messages(task["path"], task["metadata"]))
        for task in selected_tasks
    }
    total_input_tokens = sum(input_tokens_by_task.values()) * model_count * repetitions
    total_output_tokens = 0
    total_cost_usd = 0.0
    total_cost_rmb = 0.0
    per_model_lines = []

    for model in selected_models:
        model_input_tokens = sum(input_tokens_by_task.values()) * repetitions
        model_output_tokens = estimate_model_output_tokens(model, args) * task_count * repetitions
        total_output_tokens += model_output_tokens
        usage = {
            "input_tokens": model_input_tokens,
            "output_tokens": model_output_tokens,
            "total_tokens": model_input_tokens + model_output_tokens,
        }
        cost_usd = estimate_cost(model, usage, "usd")
        cost_rmb = estimate_cost(model, usage, "rmb")
        total_cost_usd += cost_usd
        total_cost_rmb += cost_rmb
        per_model_lines.append(
            f"  - {model.get('name')}: approx {model_input_tokens} input / {model_output_tokens} output tokens"
            f", estimated cost {format_cost(cost_rmb, cost_usd)}"
        )

    print("Run plan:")
    print(f"- Category: {args.category}")
    print(f"- Suite filter: {args.suite or 'all'}")
    print(f"- Capability filter: {args.capability or 'all'}")
    print(f"- Difficulty filter: {args.difficulty or 'all'}")
    print(f"- Source filter: {args.source_type or 'all'}")
    if args.sample_size:
        print(f"- Sample: {args.sample_size} task(s), seed={args.sample_seed}")
    print(f"- Models: {model_count} ({', '.join(str(model.get('name')) for model in selected_models)})")
    print(f"- Tasks: {task_count} ({', '.join(str(task['metadata'].get('id')) for task in selected_tasks)})")
    print(f"- Repetitions: {repetitions}")
    print(f"- Estimated API/model calls: {call_count}")
    print(f"- Estimated tokens: {total_input_tokens} input / {total_output_tokens} max output")
    print(f"- Estimated total cost: {format_cost(total_cost_rmb, total_cost_usd)}")
    if args.dry_run:
        print("- Mode: dry-run, no real model API calls will be made.")
    if args.plan_only:
        print("- Mode: plan-only, no results will be written.")
    print("Per-model estimate:")
    for line in per_model_lines:
        print(line)
    print("Note: token and cost estimates are approximate; real provider usage may differ.")


def estimate_messages_tokens(messages: list[dict[str, str]]) -> int:
    text = "\n".join(message.get("content", "") for message in messages)
    return max(1, len(text) // 4)


def estimate_model_output_tokens(model: dict[str, Any], args: argparse.Namespace) -> int:
    value = effective_max_tokens(str(args.category), args, model)
    try:
        return max(1, int(value or 0))
    except (TypeError, ValueError):
        return 1


def effective_max_tokens(category: str, args: argparse.Namespace, model: dict[str, Any]) -> int:
    value = args.max_tokens
    if value is None:
        value = CATEGORY_DEFAULT_MAX_TOKENS.get(category)
    if value is None:
        value = model.get("max_tokens", 4096)
    try:
        return max(1, int(value or 4096))
    except (TypeError, ValueError):
        return 4096


def format_cost(cost_rmb: float, cost_usd: float) -> str:
    parts = []
    if cost_rmb:
        parts.append(f"RMB {cost_rmb:.6f}")
    if cost_usd:
        parts.append(f"${cost_usd:.6f}")
    return " / ".join(parts) if parts else "0 (no price configured or estimated zero)"


def validate_selected_models(selected_models: list[dict[str, Any]], dry_run: bool) -> list[dict[str, str]]:
    findings = []
    if dry_run:
        return findings
    for model in selected_models:
        name = str(model.get("name") or "unknown")
        if model.get("provider") != "openai_compatible":
            continue
        api_key_env = str(model.get("api_key_env") or "")
        if not api_key_env:
            findings.append(finding("error", name, "本次选中的 API 模型缺少 api_key_env。"))
        elif not os.environ.get(api_key_env):
            findings.append(finding("error", name, f"本次选中的 API 模型缺少环境变量：{api_key_env}"))
        if not model.get("base_url"):
            findings.append(finding("error", name, "本次选中的 API 模型缺少 base_url。"))
    return findings


def select_models(config: dict[str, Any], selector: str) -> list[dict[str, Any]]:
    configured = config.get("models", [])
    if selector == "all":
        return [model for model in configured if model.get("enabled", True)]
    requested = {name.strip() for name in selector.split(",") if name.strip()}
    return [model for model in configured if model.get("name") in requested]


def discover_tasks(args: argparse.Namespace) -> list[dict[str, Any]]:
    category = str(args.category)
    selector = str(args.tasks)
    if category not in SUPPORTED_CATEGORIES:
        raise SystemExit("Supported categories: audit, log_analysis, patch, ctf, tool_use.")
    requested = None if selector == "all" else {item.strip() for item in selector.split(",") if item.strip()}
    source_types = split_filter(args.source_type)
    suites = split_filter(args.suite)
    capabilities = split_filter(args.capability)
    difficulties = split_filter(args.difficulty)
    tasks: list[dict[str, Any]] = []
    for entry in load_task_entries(PROJECT_ROOT, category=category):
        metadata = entry.get("metadata", {})
        if requested and metadata.get("id") not in requested:
            continue
        benchmark = benchmark_fields(metadata)
        if not requested and source_types and metadata.get("source", {}).get("type") not in source_types:
            continue
        if not requested and suites and benchmark["benchmark_suite"] not in suites:
            continue
        if not requested and capabilities and benchmark["benchmark_capability"] not in capabilities:
            continue
        if not requested and difficulties and str(metadata.get("difficulty") or "") not in difficulties:
            continue
        tasks.append({"metadata": metadata, "path": PROJECT_ROOT / str(entry.get("task_dir"))})
    if requested:
        return tasks
    sample_size = args.sample_size if args.sample_size is not None else args.max_tasks
    if sample_size is not None and sample_size > 0 and len(tasks) > sample_size:
        if args.sample_size is not None:
            sampler = random.Random(str(args.sample_seed))
            tasks = sorted(sampler.sample(tasks, sample_size), key=lambda item: str(item["metadata"].get("id")))
        else:
            tasks = tasks[:sample_size]
    return tasks


def split_filter(value: str | None) -> set[str] | None:
    if not value:
        return None
    items = {item.strip() for item in value.split(",") if item.strip() and item.strip() != "all"}
    return items or None


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
        final_answer = dry_run_answer(str(metadata.get("category")))
        raw_response = {
            "model": model.get("name"),
            "provider": model.get("provider"),
            "messages": messages,
            "final_answer": final_answer,
            "tool_calls": [],
            "usage": {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0},
            "latency_ms": 0,
            "cost_usd": 0.0,
            "cost_rmb": 0.0,
            "error": None,
        }
    else:
        try:
            response = call_model(
                model,
                messages,
                temperature=args.temperature,
                max_tokens=effective_max_tokens(str(metadata.get("category")), args, model),
                response_format={"type": "json_object"},
            )
            raw_response = response.to_dict()
            final_answer = response.final_answer
            if not str(final_answer or "").strip():
                metadata_hint = raw_response.get("response_metadata") or {}
                if metadata_hint.get("has_reasoning_content"):
                    error = "Provider returned empty content with reasoning_content only."
                else:
                    error = "Provider returned empty content."
                raw_response["error"] = error
        except Exception as exc:
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
                "cost_rmb": 0.0,
                "error": error,
            }

    raw_path = save_raw(run_id, str(model.get("name")), str(metadata.get("id")), raw_response)
    grade = grade_task(metadata, final_answer) if not error else None
    diagnosis = diagnose_answer(metadata, final_answer) if not error else {"issues": [error], "issue_count": 1}
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
        "expected_vuln_types": expected_types(metadata),
        "model": model.get("name"),
        "model_id": model.get("model_id"),
        "model_display": model_display_name(model),
        "provider": model.get("provider"),
        "mode": args.mode,
        "repetition": repetition,
        "temperature": args.temperature if args.temperature is not None else model.get("temperature"),
        "max_tokens": effective_max_tokens(str(metadata.get("category")), args, model),
        "max_tokens_source": "override" if args.max_tokens is not None else "category_default",
        "max_turns": metadata.get("execution", {}).get("max_turns", 1),
        "success": bool(grade.success) if grade else False,
        "score": int(grade.score) if grade else 0,
        "grader": grade.grader if grade else "not_graded",
        "grade_details": grade.details if grade else {"error": error},
        "answer_diagnosis": diagnosis,
        "latency_ms": raw_response.get("latency_ms", 0),
        "usage": raw_response.get("usage", {}),
        "cost_usd": raw_response.get("cost_usd", 0.0),
        "cost_rmb": raw_response.get("cost_rmb", 0.0),
        "final_answer_path": str(raw_path.relative_to(PROJECT_ROOT)),
        "tool_log_path": None,
        "error": error,
        "created_at": now,
    }
    row.update(benchmark_fields(metadata))
    row["weighted_score_points"] = float(row["score"]) * float(row.get("effective_weight", 0) or 0)
    row["weighted_success_points"] = (1.0 if row["success"] else 0.0) * float(row.get("effective_weight", 0) or 0)
    return row


def build_messages(task_path: Path, metadata: dict[str, Any]) -> list[dict[str, str]]:
    system_prompt = (PROJECT_ROOT / "prompts" / "system_security_eval.txt").read_text(encoding="utf-8")
    category = str(metadata.get("category", "audit"))
    if category == "log_analysis":
        task_type_prompt = (PROJECT_ROOT / "prompts" / "log_analysis_prompt.txt").read_text(encoding="utf-8")
        schema = (PROJECT_ROOT / "prompts" / "log_output_schema.txt").read_text(encoding="utf-8")
    elif category == "patch":
        task_type_prompt = (PROJECT_ROOT / "prompts" / "patch_prompt.txt").read_text(encoding="utf-8")
        schema = (PROJECT_ROOT / "prompts" / "patch_output_schema.txt").read_text(encoding="utf-8")
    elif category == "ctf":
        task_type_prompt = (PROJECT_ROOT / "prompts" / "ctf_prompt.txt").read_text(encoding="utf-8")
        schema = (PROJECT_ROOT / "prompts" / "ctf_output_schema.txt").read_text(encoding="utf-8")
    elif category == "tool_use":
        task_type_prompt = (PROJECT_ROOT / "prompts" / "tool_use_prompt.txt").read_text(encoding="utf-8")
        schema = (PROJECT_ROOT / "prompts" / "tool_use_output_schema.txt").read_text(encoding="utf-8")
    else:
        task_type_prompt = (PROJECT_ROOT / "prompts" / "audit_prompt.txt").read_text(encoding="utf-8")
        schema = (PROJECT_ROOT / "prompts" / "json_output_schema.txt").read_text(encoding="utf-8")
    task_prompt = (task_path / metadata["prompt_file"]).read_text(encoding="utf-8")
    file_blocks = []
    for relative in metadata.get("files", []):
        file_path = task_path / relative
        content = file_path.read_text(encoding="utf-8")
        file_blocks.append(f"## File: {relative}\n```text\n{content}\n```")
    user_content = "\n\n".join(
        [
            task_type_prompt,
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


def dry_run_answer(category: str) -> str:
    if category == "log_analysis":
        return json.dumps(
            {
                "attack_type": "dry run",
                "evidence": [],
                "timeline": [],
                "impact": "dry run",
                "remediation": [],
                "confidence": 0,
                "summary": "dry run",
            },
            ensure_ascii=False,
        )
    if category == "patch":
        return json.dumps(
            {
                "vulnerability": "dry run",
                "root_cause": "dry run",
                "affected_locations": [],
                "patch": [],
                "tests": [],
                "impact": "dry run",
                "confidence": 0,
                "summary": "dry run",
            },
            ensure_ascii=False,
        )
    if category == "ctf":
        return json.dumps(
            {
                "flag": "",
                "method": "dry run",
                "evidence": [],
                "commands": [],
                "confidence": 0,
                "summary": "dry run",
            },
            ensure_ascii=False,
        )
    if category == "tool_use":
        return json.dumps(
            {
                "objective": "dry run",
                "tool_plan": [],
                "final_answer": {
                    "conclusion": "dry run",
                    "evidence": [],
                    "recommended_actions": [],
                    "uncertainty": "dry run",
                },
                "safety_notes": [],
                "confidence": 0,
                "summary": "dry run",
            },
            ensure_ascii=False,
        )
    return json.dumps({"findings": [], "summary": "dry run"}, ensure_ascii=False)


def grade_task(metadata: dict[str, Any], final_answer: str):
    if metadata.get("category") == "log_analysis":
        return grade_log_analysis(metadata, final_answer)
    if metadata.get("category") == "patch":
        return grade_patch(metadata, final_answer)
    if metadata.get("category") == "ctf":
        return grade_ctf(metadata, final_answer)
    if metadata.get("category") == "tool_use":
        return grade_tool_use(metadata, final_answer)
    return grade_audit(metadata, final_answer)


def diagnose_answer(metadata: dict[str, Any], final_answer: str) -> dict[str, Any]:
    if metadata.get("category") == "log_analysis":
        return diagnose_log_answer(metadata, final_answer)
    if metadata.get("category") == "patch":
        return diagnose_patch_answer(metadata, final_answer)
    if metadata.get("category") == "ctf":
        return diagnose_ctf_answer(metadata, final_answer)
    if metadata.get("category") == "tool_use":
        return diagnose_tool_use_answer(metadata, final_answer)
    return diagnose_audit_answer(metadata, final_answer)


def expected_types(metadata: dict[str, Any]) -> list[str]:
    expected = metadata.get("expected", {})
    types = [
        str(vuln.get("type", "unknown"))
        for vuln in expected.get("vulnerabilities", [])
        if isinstance(vuln, dict)
    ]
    fallback = (
        expected.get("attack_type")
        or expected.get("vulnerability_type")
        or expected.get("flag_type")
        or expected.get("tool_goal")
        or "unknown"
    )
    return types or [str(fallback)]


def model_display_name(model: dict[str, Any]) -> str:
    name = str(model.get("name") or "unknown")
    model_id = str(model.get("model_id") or "")
    if model_id and model_id != name:
        return f"{name} / {model_id}"
    return name


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
    print(f"Weighted benchmark score: {benchmark_score(rows):.1f}")
    print(f"Weighted solve rate: {benchmark_solve_rate(rows):.1%}")


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
