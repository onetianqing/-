from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import threading
import time
import webbrowser
from datetime import datetime
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from runners.benchmark import benchmark_fields, benchmark_score, benchmark_solve_rate, enrich_row as enrich_benchmark_row
from runners.config_loader import load_yaml
from runners.task_index import load_task_entries, load_task_metadata_map as indexed_task_metadata_map, public_task_record, task_index_status


JOBS: dict[str, dict[str, Any]] = {}
JOBS_LOCK = threading.Lock()
RUN_ID_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{1,80}$")
CATEGORY_DEFAULT_MAX_TOKENS = {
    "audit": 4096,
    "log_analysis": 4096,
    "patch": 4096,
    "ctf": 4096,
    "tool_use": 4096,
}


class PlatformHandler(SimpleHTTPRequestHandler):
    server_version = "SecurityEvalPlatform/0.17"

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = unquote(parsed.path)
        if path in {"/", "/index.html"}:
            self.send_file(PROJECT_ROOT / "ui" / "static" / "index.html", "text/html; charset=utf-8")
            return
        if path == "/api/state":
            self.send_json(platform_state())
            return
        if path == "/api/runs":
            self.send_json(runs_index())
            return
        if path.startswith("/api/runs/"):
            run_id = validate_run_id(path.rsplit("/", 1)[-1])
            self.send_json(run_detail(run_id))
            return
        if path == "/api/tasks/catalog":
            self.send_json(tasks_catalog())
            return
        if path.startswith("/api/jobs/"):
            job_id = path.rsplit("/", 1)[-1]
            with JOBS_LOCK:
                job = dict(JOBS.get(job_id) or {})
            if not job:
                self.send_error_json(404, "任务不存在。")
                return
            job = enrich_job_snapshot(job)
            self.send_json(job)
            return
        if path.startswith("/reports/"):
            self.send_report_file(path)
            return
        if path.startswith("/static/"):
            self.send_static_file(path)
            return
        self.send_error_json(404, "路径不存在。")

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        try:
            payload = self.read_json()
            if path == "/api/plan":
                command = build_eval_command(payload, plan_only=True)
                completed = run_command(command)
                self.send_json(
                    {
                        "ok": completed.returncode == 0,
                        "command": printable_command(command),
                        "output": completed.stdout + completed.stderr,
                        "returncode": completed.returncode,
                    }
                )
                return
            if path == "/api/run":
                job = create_job(payload)
                self.send_json(job)
                return
            if path == "/api/report":
                run_id = validate_run_id(str(payload.get("run_id") or ""))
                completed = run_command([sys.executable, "reports/generate_report.py", "--run-id", run_id])
                self.send_json(
                    {
                        "ok": completed.returncode == 0,
                        "run_id": run_id,
                        "output": completed.stdout + completed.stderr,
                        "report_html": f"/reports/{run_id}.html",
                        "report_md": f"/reports/{run_id}.md",
                    }
                )
                return
            self.send_error_json(404, "路径不存在。")
        except ValueError as exc:
            self.send_error_json(400, str(exc))
        except Exception as exc:  # pragma: no cover - defensive server boundary
            self.send_error_json(500, f"服务端错误：{exc}")

    def read_json(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0") or 0)
        raw = self.rfile.read(length).decode("utf-8")
        if not raw.strip():
            return {}
        data = json.loads(raw)
        if not isinstance(data, dict):
            raise ValueError("请求体必须是 JSON 对象。")
        return data

    def send_json(self, data: dict[str, Any], status: int = 200) -> None:
        body = json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def send_error_json(self, status: int, message: str) -> None:
        self.send_json({"ok": False, "error": message}, status=status)

    def send_file(self, path: Path, content_type: str) -> None:
        if not path.exists() or not path.is_file():
            self.send_error_json(404, "文件不存在。")
            return
        body = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_static_file(self, request_path: str) -> None:
        relative = request_path.removeprefix("/static/").lstrip("/")
        safe_path = safe_join(PROJECT_ROOT / "ui" / "static", relative)
        content_type = "text/css; charset=utf-8" if safe_path.suffix == ".css" else "application/javascript; charset=utf-8"
        self.send_file(safe_path, content_type)

    def send_report_file(self, request_path: str) -> None:
        relative = request_path.removeprefix("/reports/").lstrip("/")
        safe_path = safe_join(PROJECT_ROOT / "results" / "reports", relative)
        suffix = safe_path.suffix.lower()
        content_type = "text/html; charset=utf-8" if suffix == ".html" else "text/markdown; charset=utf-8"
        self.send_file(safe_path, content_type)

    def log_message(self, format: str, *args: Any) -> None:
        print(f"[ui] {self.address_string()} - {format % args}")


def platform_state() -> dict[str, Any]:
    models = load_models()
    tasks = load_tasks()
    reports = load_reports()
    categories = sorted({task["category"] for task in tasks})
    source_types = sorted({task["source_type"] for task in tasks if task.get("source_type")})
    suites = sorted({task["benchmark_suite"] for task in tasks if task.get("benchmark_suite")})
    capabilities = sorted({task["benchmark_capability"] for task in tasks if task.get("benchmark_capability")})
    difficulties = sorted({task["difficulty"] for task in tasks if task.get("difficulty")})
    return {
        "ok": True,
        "task_index": task_index_status(PROJECT_ROOT),
        "models": models,
        "categories": categories,
        "source_types": source_types,
        "suites": suites,
        "capabilities": capabilities,
        "difficulties": difficulties,
        "tasks": tasks,
        "reports": reports,
        "defaults": {
            "category": "audit" if "audit" in categories else (categories[0] if categories else ""),
            "repetitions": 1,
            "run_id": f"ui-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            "max_tokens_by_category": CATEGORY_DEFAULT_MAX_TOKENS,
            "default_max_tokens": 4096,
        },
    }


def load_models() -> list[dict[str, Any]]:
    config = load_yaml(PROJECT_ROOT / "config" / "models.yaml")
    models = []
    for model in config.get("models", []):
        api_key_env = str(model.get("api_key_env") or "")
        models.append(
            {
                "name": model.get("name"),
                "enabled": bool(model.get("enabled", True)),
                "provider": model.get("provider"),
                "model_id": model.get("model_id"),
                "api_key_env": api_key_env,
                "api_key_ready": bool(api_key_env and os.environ.get(api_key_env)),
                "max_tokens": model.get("max_tokens"),
                "temperature": model.get("temperature"),
                "rmb_input": model.get("rmb_per_1m_input_tokens", 0),
                "rmb_output": model.get("rmb_per_1m_output_tokens", 0),
            }
        )
    return models


def load_tasks() -> list[dict[str, Any]]:
    return [public_task_record(entry) for entry in load_task_entries(PROJECT_ROOT)]


def load_reports() -> list[dict[str, Any]]:
    scored_dir = PROJECT_ROOT / "results" / "scored"
    report_dir = PROJECT_ROOT / "results" / "reports"
    reports = []
    for path in sorted(scored_dir.glob("*.jsonl"), reverse=True):
        run_id = path.stem
        reports.append(
            {
                "run_id": run_id,
                "scored_path": str(path.relative_to(PROJECT_ROOT)),
                "html": f"/reports/{run_id}.html" if (report_dir / f"{run_id}.html").exists() else "",
                "md": f"/reports/{run_id}.md" if (report_dir / f"{run_id}.md").exists() else "",
                "updated_at": datetime.fromtimestamp(path.stat().st_mtime).isoformat(timespec="seconds"),
            }
        )
    return reports[:50]


def runs_index() -> dict[str, Any]:
    scored_dir = PROJECT_ROOT / "results" / "scored"
    task_meta = load_task_metadata_map()
    runs = []
    for path in sorted(scored_dir.glob("*.jsonl"), reverse=True):
        run_id = path.stem
        rows = enrich_scored_rows(load_scored_rows(path), task_meta)
        runs.append(run_summary(run_id, rows, path))
    return {"ok": True, "runs": runs}


def run_detail(run_id: str) -> dict[str, Any]:
    scored_path = PROJECT_ROOT / "results" / "scored" / f"{run_id}.jsonl"
    if not scored_path.exists():
        raise ValueError(f"run 不存在：{run_id}")
    task_meta = load_task_metadata_map()
    rows = enrich_scored_rows(load_scored_rows(scored_path), task_meta)
    results = [result_detail(row, task_meta) for row in rows]
    return {
        "ok": True,
        "run": run_summary(run_id, rows, scored_path),
        "results": results,
        "scored_path": str(scored_path.relative_to(PROJECT_ROOT)),
    }


def tasks_catalog() -> dict[str, Any]:
    tasks = load_tasks()
    grouped: dict[str, list[dict[str, Any]]] = {}
    for task in tasks:
        grouped.setdefault(str(task.get("category") or "unknown"), []).append(task)
    categories = []
    for category, items in sorted(grouped.items()):
        source_types = sorted({str(item.get("source_type") or "unknown") for item in items})
        difficulties = sorted({str(item.get("difficulty") or "unknown") for item in items})
        categories.append(
            {
                "category": category,
                "count": len(items),
                "source_types": source_types,
                "difficulties": difficulties,
                "tasks": sorted(items, key=lambda item: str(item.get("id") or "")),
            }
        )
    return {"ok": True, "task_index": task_index_status(PROJECT_ROOT), "categories": categories, "tasks": tasks}


def load_scored_rows(path: Path) -> list[dict[str, Any]]:
    rows = []
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                rows.append(json.loads(line))
    except (OSError, json.JSONDecodeError):
        return []
    return rows


def enrich_scored_rows(rows: list[dict[str, Any]], task_meta: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    return [enrich_benchmark_row(row, task_meta.get(str(row.get("task_id") or ""), {})) for row in rows]


def load_task_metadata_map() -> dict[str, dict[str, Any]]:
    return indexed_task_metadata_map(PROJECT_ROOT)


def run_summary(run_id: str, rows: list[dict[str, Any]], scored_path: Path) -> dict[str, Any]:
    report_dir = PROJECT_ROOT / "results" / "reports"
    scores = [float(row.get("score", 0) or 0) for row in rows]
    success_count = sum(1 for row in rows if row.get("success"))
    tokens = [total_tokens(row) for row in rows]
    categories = sorted({str(row.get("category") or "unknown") for row in rows})
    models = sorted({str(row.get("model_display") or model_display(row)) for row in rows})
    tasks = sorted({str(row.get("task_id") or "") for row in rows if row.get("task_id")})
    return {
        "run_id": run_id,
        "count": len(rows),
        "models": models,
        "categories": categories,
        "task_count": len(tasks),
        "tasks": tasks,
        "avg_score": round(sum(scores) / len(scores), 2) if scores else 0,
        "weighted_score": round(benchmark_score(rows), 2),
        "success_rate": round(success_count / len(rows), 4) if rows else 0,
        "weighted_solve_rate": round(benchmark_solve_rate(rows), 4),
        "total_tokens": int(sum(tokens)),
        "total_cost_rmb": round(sum(cost_value(row, "rmb") for row in rows), 8),
        "total_cost_usd": round(sum(cost_value(row, "usd") for row in rows), 8),
        "html": f"/reports/{run_id}.html" if (report_dir / f"{run_id}.html").exists() else "",
        "md": f"/reports/{run_id}.md" if (report_dir / f"{run_id}.md").exists() else "",
        "scored_path": str(scored_path.relative_to(PROJECT_ROOT)),
        "updated_at": datetime.fromtimestamp(scored_path.stat().st_mtime).isoformat(timespec="seconds"),
    }


def result_detail(row: dict[str, Any], task_meta: dict[str, dict[str, Any]]) -> dict[str, Any]:
    task_id = str(row.get("task_id") or "")
    metadata = task_meta.get(task_id, {})
    raw = load_raw_response(str(row.get("final_answer_path") or ""))
    return {
        "run_id": row.get("run_id"),
        "model": row.get("model"),
        "model_id": row.get("model_id"),
        "model_display": row.get("model_display") or model_display(row),
        "task_id": task_id,
        "task_title": row.get("task_title") or metadata.get("title"),
        "category": row.get("category") or metadata.get("category"),
        "difficulty": row.get("difficulty") or metadata.get("difficulty"),
        "score": int(row.get("score", 0) or 0),
        "weighted_score_points": round(float(row.get("weighted_score_points", 0) or 0), 4),
        "success": bool(row.get("success")),
        "grader": row.get("grader"),
        "latency_ms": int(row.get("latency_ms", 0) or 0),
        "usage": row.get("usage") or {},
        "cost_rmb": cost_value(row, "rmb"),
        "cost_usd": cost_value(row, "usd"),
        "max_tokens": row.get("max_tokens"),
        "max_tokens_source": row.get("max_tokens_source"),
        "benchmark_suite": row.get("benchmark_suite"),
        "benchmark_capability": row.get("benchmark_capability"),
        "benchmark_weight": row.get("benchmark_weight"),
        "difficulty_weight": row.get("difficulty_weight"),
        "effective_weight": row.get("effective_weight"),
        "leakage_risk": row.get("leakage_risk"),
        "components": component_rows(row),
        "deductions": deduction_items(row),
        "diagnosis": row.get("answer_diagnosis") or {},
        "response_metadata": raw.get("response_metadata", {}),
        "raw_path": row.get("final_answer_path"),
        "raw_preview": str(raw.get("final_answer") or "")[:1200],
        "error": row.get("error"),
        "created_at": row.get("created_at"),
    }


def load_raw_response(relative_path: str) -> dict[str, Any]:
    if not relative_path:
        return {}
    raw_path = safe_join(PROJECT_ROOT, relative_path.replace("\\", "/"))
    try:
        if raw_path.exists() and raw_path.is_file():
            return json.loads(raw_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, ValueError):
        return {}
    return {}


def component_rows(row: dict[str, Any]) -> list[dict[str, Any]]:
    labels = component_labels(str(row.get("category") or ""))
    scoring = row.get("scoring_items") or {}
    per_expected = (row.get("grade_details") or {}).get("per_expected") or []
    first = per_expected[0] if per_expected else {}
    items = first.get("items") or {}
    components = []
    for key in ["vulnerability_type", "location_accuracy", "root_cause", "exploitability", "fix_quality"]:
        value = float(items.get(key, 0) or 0)
        max_points = float(scoring.get(key, value) or value)
        components.append({"key": key, "label": labels.get(key, key), "score": value, "max": max_points})
    return components


def component_labels(category: str) -> dict[str, str]:
    if category == "tool_use":
        return {
            "vulnerability_type": "工具选择",
            "location_accuracy": "参数准确",
            "root_cause": "步骤顺序",
            "exploitability": "证据结论",
            "fix_quality": "安全边界",
        }
    return {
        "vulnerability_type": "类型判断",
        "location_accuracy": "关键证据/定位",
        "root_cause": "根因/时间线",
        "exploitability": "复现/影响判断",
        "fix_quality": "修复/处置建议",
    }


def deduction_items(row: dict[str, Any]) -> list[str]:
    details = row.get("grade_details") or {}
    reasons: list[str] = []
    for expected in details.get("per_expected", []) or []:
        deductions = expected.get("deductions")
        if isinstance(deductions, dict):
            for value in deductions.values():
                if value and str(value) not in reasons:
                    reasons.append(str(value))
    if row.get("error"):
        reasons.append(f"调用错误：{row.get('error')}")
    parse_error = details.get("parse_error")
    if parse_error:
        reasons.append(f"JSON 解析问题：{parse_error}")
    return reasons


def model_display(row: dict[str, Any]) -> str:
    name = str(row.get("model") or "unknown")
    model_id = str(row.get("model_id") or "")
    return f"{name} / {model_id}" if model_id and model_id != name else name


def total_tokens(row: dict[str, Any]) -> float:
    usage = row.get("usage") or {}
    try:
        return float(usage.get("total_tokens", 0) or 0)
    except (TypeError, ValueError):
        return 0.0


def cost_value(row: dict[str, Any], currency: str) -> float:
    try:
        return float(row.get(f"cost_{currency}", 0) or 0)
    except (TypeError, ValueError):
        return 0.0


def build_eval_command(payload: dict[str, Any], plan_only: bool = False) -> list[str]:
    models = validate_selection(payload.get("models"), {str(model["name"]) for model in load_models()})
    tasks = payload.get("tasks")
    category = str(payload.get("category") or "")
    known_tasks = {str(task["id"]) for task in load_tasks() if task.get("category") == category}
    if category not in {task["category"] for task in load_tasks()}:
        raise ValueError("请选择有效的测试类别。")
    repetitions = validate_int(payload.get("repetitions", 1), "测试次数", 1, 20)
    command = [
        sys.executable,
        "runners/run_eval.py",
        "--models",
        ",".join(models),
        "--category",
        category,
        "--repetitions",
        str(repetitions),
    ]
    selected_tasks = validate_optional_selection(tasks, known_tasks)
    if selected_tasks:
        command.extend(["--tasks", ",".join(selected_tasks)])
    else:
        command.extend(["--tasks", "all"])
        source_type = str(payload.get("source_type") or "all")
        if source_type != "all":
            command.extend(["--source-type", source_type])
        suite = str(payload.get("suite") or "all")
        if suite != "all":
            command.extend(["--suite", suite])
        capability = str(payload.get("capability") or "all")
        if capability != "all":
            command.extend(["--capability", capability])
        difficulty = str(payload.get("difficulty") or "all")
        if difficulty != "all":
            command.extend(["--difficulty", difficulty])
    if payload.get("max_tasks"):
        command.extend(["--max-tasks", str(validate_int(payload.get("max_tasks"), "最大任务数", 1, 100000))])
    if payload.get("sample_size"):
        command.extend(["--sample-size", str(validate_int(payload.get("sample_size"), "抽样题目量", 1, 100000))])
    if payload.get("sample_seed"):
        command.extend(["--sample-seed", str(payload.get("sample_seed"))[:80]])
    if payload.get("max_tokens"):
        command.extend(["--max-tokens", str(validate_int(payload.get("max_tokens"), "最大输出 token", 1, 200000))])
    if payload.get("dry_run"):
        command.append("--dry-run")
    if payload.get("preflight", True) or plan_only:
        command.append("--preflight")
    if payload.get("preflight_strict"):
        command.append("--preflight-strict")
    if plan_only:
        command.append("--plan-only")
    else:
        run_id = validate_run_id(str(payload.get("run_id") or f"ui-{datetime.now().strftime('%Y%m%d-%H%M%S')}"))
        command.extend(["--run-id", run_id])
    return command


def create_job(payload: dict[str, Any]) -> dict[str, Any]:
    command = build_eval_command(payload, plan_only=False)
    run_id = command[command.index("--run-id") + 1]
    job_id = f"job-{datetime.now().strftime('%Y%m%d-%H%M%S')}-{len(JOBS) + 1}"
    total_calls = estimate_total_calls(payload)
    job = {
        "ok": True,
        "job_id": job_id,
        "run_id": run_id,
        "status": "queued",
        "command": printable_command(command),
        "output": "",
        "log_path": f"results/job_logs/{run_id}.log",
        "progress": {
            "done": 0,
            "total": total_calls,
            "percent": 0,
            "elapsed_seconds": 0,
            "started_at": None,
            "finished_at": None,
            "current": "等待开始",
        },
        "report_html": "",
        "report_md": "",
        "created_at": datetime.now().isoformat(timespec="seconds"),
    }
    with JOBS_LOCK:
        JOBS[job_id] = job
    log_path = PROJECT_ROOT / "results" / "job_logs" / f"{run_id}.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.write_text(printable_command(command) + "\n", encoding="utf-8")
    thread = threading.Thread(target=run_job, args=(job_id, command, run_id), daemon=True)
    thread.start()
    return job


def run_job(job_id: str, command: list[str], run_id: str) -> None:
    started = time.time()
    update_job(
        job_id,
        status="running",
        progress_updates={"started_at": started, "current": "正在执行评测"},
    )
    eval_code = run_streaming_command(job_id, command)
    if eval_code != 0:
        update_job(
            job_id,
            status="failed",
            progress_updates={"finished_at": time.time(), "current": "评测失败"},
        )
        return
    report_command = [sys.executable, "reports/generate_report.py", "--run-id", run_id]
    append_job_output(job_id, "\n\n" + printable_command(report_command) + "\n")
    update_job(job_id, progress_updates={"current": "正在生成报告"})
    report_code = run_streaming_command(job_id, report_command, count_progress=False)
    status = "completed" if report_code == 0 else "failed"
    current = "评测完成" if status == "completed" else "报告生成失败"
    update_job(
        job_id,
        status=status,
        progress_updates={"finished_at": time.time(), "current": current},
        report_html=f"/reports/{run_id}.html",
        report_md=f"/reports/{run_id}.md",
    )


def run_streaming_command(job_id: str, command: list[str], count_progress: bool = True) -> int:
    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    process = subprocess.Popen(
        command,
        cwd=PROJECT_ROOT,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env=env,
    )
    assert process.stdout is not None
    for line in process.stdout:
        append_job_output(job_id, line)
        if count_progress and line.startswith("[rep "):
            increment_job_progress(job_id, line.strip())
    return process.wait()


def run_command(command: list[str]) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    return subprocess.run(
        command,
        cwd=PROJECT_ROOT,
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        env=env,
    )


def update_job(job_id: str, progress_updates: dict[str, Any] | None = None, **changes: Any) -> None:
    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if not job:
            return
        job.update(changes)
        if progress_updates:
            progress = job.setdefault("progress", {})
            progress.update(progress_updates)
            refresh_progress(progress)
        job["updated_at"] = datetime.now().isoformat(timespec="seconds")


def append_job_output(job_id: str, text: str) -> None:
    log_path: Path | None = None
    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if not job:
            return
        output = (job.get("output") or "") + text
        job["output"] = output[-120000:]
        if job.get("log_path"):
            log_path = PROJECT_ROOT / str(job["log_path"])
        progress = job.setdefault("progress", {})
        refresh_progress(progress)
        job["updated_at"] = datetime.now().isoformat(timespec="seconds")
    if log_path:
        try:
            with log_path.open("a", encoding="utf-8") as handle:
                handle.write(text)
        except OSError:
            pass


def increment_job_progress(job_id: str, current: str) -> None:
    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if not job:
            return
        progress = job.setdefault("progress", {})
        total = int(progress.get("total") or 0)
        done = min(int(progress.get("done") or 0) + 1, total if total else 10**9)
        progress.update({"done": done, "current": current})
        refresh_progress(progress)
        job["updated_at"] = datetime.now().isoformat(timespec="seconds")


def refresh_progress(progress: dict[str, Any]) -> None:
    started_at = progress.get("started_at")
    finished_at = progress.get("finished_at")
    if started_at:
        end = float(finished_at or time.time())
        progress["elapsed_seconds"] = max(0, int(end - float(started_at)))
    total = int(progress.get("total") or 0)
    done = int(progress.get("done") or 0)
    progress["percent"] = int(done * 100 / total) if total else 0


def enrich_job_snapshot(job: dict[str, Any]) -> dict[str, Any]:
    progress = dict(job.get("progress") or {})
    refresh_progress(progress)
    job["progress"] = progress
    return job


def estimate_total_calls(payload: dict[str, Any]) -> int:
    models = validate_selection(payload.get("models"), {str(model["name"]) for model in load_models()})
    category = str(payload.get("category") or "")
    all_tasks = [task for task in load_tasks() if task.get("category") == category]
    selected_tasks = validate_optional_selection(payload.get("tasks"), {str(task["id"]) for task in all_tasks})
    if selected_tasks:
        tasks = [task for task in all_tasks if str(task.get("id")) in set(selected_tasks)]
    else:
        source_type = str(payload.get("source_type") or "all")
        suite = str(payload.get("suite") or "all")
        capability = str(payload.get("capability") or "all")
        difficulty = str(payload.get("difficulty") or "all")
        tasks = [
            task for task in all_tasks
            if (source_type == "all" or task.get("source_type") == source_type)
            and (suite == "all" or task.get("benchmark_suite") == suite)
            and (capability == "all" or task.get("benchmark_capability") == capability)
            and (difficulty == "all" or task.get("difficulty") == difficulty)
        ]
        sample_size = payload.get("sample_size") or payload.get("max_tasks")
        if sample_size:
            tasks = tasks[: validate_int(sample_size, "抽样题目量", 1, 100000)]
    repetitions = validate_int(payload.get("repetitions", 1), "测试次数", 1, 20)
    return max(1, len(models) * len(tasks) * repetitions)


def validate_selection(value: Any, allowed: set[str]) -> list[str]:
    if not isinstance(value, list) or not value:
        raise ValueError("请选择至少一个模型。")
    selected = [str(item) for item in value if str(item) in allowed]
    if not selected:
        raise ValueError("模型选择无效。")
    return selected


def validate_optional_selection(value: Any, allowed: set[str]) -> list[str]:
    if not value:
        return []
    if not isinstance(value, list):
        raise ValueError("任务选择必须是数组。")
    selected = [str(item) for item in value if str(item) in allowed]
    if not selected:
        raise ValueError("任务选择无效。")
    return selected


def validate_int(value: Any, label: str, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{label}必须是整数。") from exc
    if parsed < minimum or parsed > maximum:
        raise ValueError(f"{label}必须在 {minimum} 到 {maximum} 之间。")
    return parsed


def validate_run_id(value: str) -> str:
    if not value or not RUN_ID_PATTERN.match(value):
        raise ValueError("run_id 只能包含英文、数字、下划线、点和短横线，长度不超过 80。")
    return value


def printable_command(command: list[str]) -> str:
    return " ".join(command)


def safe_join(root: Path, relative: str) -> Path:
    target = (root / relative).resolve()
    root_resolved = root.resolve()
    if root_resolved != target and root_resolved not in target.parents:
        raise ValueError("非法文件路径。")
    return target


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Start the local security evaluation web UI.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--open", action="store_true", help="Open the UI in the default browser.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    server = ThreadingHTTPServer((args.host, args.port), PlatformHandler)
    url = f"http://{args.host}:{args.port}/"
    print(f"Security evaluation UI: {url}")
    print(f"Project root: {PROJECT_ROOT}")
    print("Press Ctrl+C to stop.")
    if args.open:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("Stopping UI server.")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
