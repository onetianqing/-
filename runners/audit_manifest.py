from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from runners.ctf_consistency import configured_check_types, decode_candidates, normalized_expected_flags
from runners.import_tasks import load_manifest, plan_import
from runners.validate import finding, has_errors


def main() -> int:
    args = parse_args()
    try:
        manifest = load_manifest(PROJECT_ROOT / args.manifest)
        operations = plan_import(manifest, overwrite=True)
    except ValueError as exc:
        result = {
            "ok": False,
            "stats": {},
            "findings": [finding("error", "manifest", str(exc))],
        }
        emit_result(result, args)
        return 1

    result = audit_operations(operations)
    emit_result(result, args)
    return 1 if has_errors(result["findings"]) else 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Audit a task import manifest before importing it.")
    parser.add_argument("--manifest", required=True, help="Manifest path relative to project root, JSON or YAML.")
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON.")
    parser.add_argument("--report", default=None, help="Write a Markdown audit report relative to project root.")
    return parser.parse_args()


def audit_operations(operations: list[dict[str, Any]]) -> dict[str, Any]:
    findings: list[dict[str, str]] = []
    stats = empty_stats()
    seen_ids: set[str] = set()

    for operation in operations:
        metadata = operation["metadata"]
        task_id = str(operation["task_id"])
        update_stats(stats, metadata)
        if task_id in seen_ids:
            findings.append(finding("error", task_id, "manifest contains duplicate task id."))
        seen_ids.add(task_id)
        findings.extend(audit_source(task_id, metadata))
        findings.extend(audit_benchmark(task_id, metadata))
        findings.extend(audit_files(task_id, operation.get("files", {})))
        findings.extend(audit_prompt(task_id, operation.get("prompt_text", "")))
        if metadata.get("category") == "ctf":
            findings.extend(audit_ctf_task(task_id, metadata, operation.get("files", {})))

    stats["task_count"] = len(operations)
    stats["finding_count"] = len(findings)
    stats["error_count"] = sum(1 for item in findings if item.get("level") == "error")
    stats["warning_count"] = sum(1 for item in findings if item.get("level") == "warning")
    return {"ok": not has_errors(findings), "stats": stats, "findings": findings}


def empty_stats() -> dict[str, Any]:
    return {
        "task_count": 0,
        "categories": {},
        "source_types": {},
        "licenses": {},
        "capabilities": {},
        "difficulties": {},
    }


def update_stats(stats: dict[str, Any], metadata: dict[str, Any]) -> None:
    source = metadata.get("source", {}) if isinstance(metadata.get("source"), dict) else {}
    benchmark = metadata.get("benchmark", {}) if isinstance(metadata.get("benchmark"), dict) else {}
    bump(stats["categories"], str(metadata.get("category") or "unknown"))
    bump(stats["source_types"], str(source.get("type") or "unknown"))
    bump(stats["licenses"], str(source.get("license") or "unknown"))
    bump(stats["capabilities"], str(benchmark.get("capability") or metadata.get("sub_category") or "unknown"))
    bump(stats["difficulties"], str(metadata.get("difficulty") or "unknown"))


def bump(bucket: dict[str, int], key: str) -> None:
    bucket[key] = bucket.get(key, 0) + 1


def audit_source(task_id: str, metadata: dict[str, Any]) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    source = metadata.get("source")
    if not isinstance(source, dict):
        return [finding("error", task_id, "source must be an object.")]
    for field in ["type", "origin", "license"]:
        if not source.get(field):
            findings.append(finding("error", task_id, f"source.{field} is required."))
    source_type = str(source.get("type") or "")
    if source_type != "synthetic" and not source.get("reference_url"):
        findings.append(finding("error", task_id, "non-synthetic source requires source.reference_url."))
    if source_type == "synthetic":
        findings.append(finding("warning", task_id, "synthetic tasks should not dominate main benchmark imports."))
    if source.get("reference_url") and not str(source.get("reference_url")).startswith(("http://", "https://")):
        findings.append(finding("warning", task_id, "source.reference_url should be an HTTP(S) URL."))
    if source_type.startswith("public") and not source.get("adaptation") and not source.get("reference_note"):
        findings.append(finding("warning", task_id, "public-source tasks should describe adaptation/reference notes."))
    return findings


def audit_benchmark(task_id: str, metadata: dict[str, Any]) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    benchmark = metadata.get("benchmark")
    if not isinstance(benchmark, dict):
        return [finding("error", task_id, "benchmark must be an object.")]
    for field in ["suite", "capability"]:
        if not benchmark.get(field):
            findings.append(finding("error", task_id, f"benchmark.{field} is required."))
    for field in ["weight", "difficulty_weight"]:
        if field not in benchmark:
            findings.append(finding("warning", task_id, f"benchmark.{field} is recommended."))
            continue
        try:
            value = float(benchmark.get(field))
        except (TypeError, ValueError):
            findings.append(finding("error", task_id, f"benchmark.{field} must be numeric."))
            continue
        if value <= 0:
            findings.append(finding("error", task_id, f"benchmark.{field} must be positive."))
    return findings


def audit_files(task_id: str, files: dict[str, str]) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    if not files:
        return [finding("error", task_id, "task must include at least one file or artifact.")]
    for relative, content in files.items():
        if not str(content).strip():
            findings.append(finding("error", task_id, f"file is empty: {relative}"))
        if len(str(content).encode("utf-8")) > 1024 * 1024:
            findings.append(finding("warning", task_id, f"file is larger than 1MB and may slow prompt construction: {relative}"))
    return findings


def audit_prompt(task_id: str, prompt_text: str) -> list[dict[str, str]]:
    if not str(prompt_text).strip():
        return [finding("error", task_id, "prompt cannot be empty.")]
    if len(str(prompt_text)) < 20:
        return [finding("warning", task_id, "prompt is very short.")]
    return []


def audit_ctf_task(task_id: str, metadata: dict[str, Any], files: dict[str, str]) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    expected = metadata.get("expected", {}) if isinstance(metadata.get("expected"), dict) else {}
    for field in ["flag", "flag_type", "flag_format", "evidence_keywords", "method_keywords", "reproduction_keywords"]:
        if not expected.get(field):
            findings.append(finding("error", task_id, f"expected.{field} is required for CTF tasks."))
    findings.extend(audit_ctf_consistency(task_id, metadata, files))
    return findings


def audit_ctf_consistency(task_id: str, metadata: dict[str, Any], files: dict[str, str]) -> list[dict[str, str]]:
    check_types = configured_check_types(metadata)
    if not check_types:
        return []
    expected_flags = normalized_expected_flags(metadata)
    if not expected_flags:
        return []
    candidates: set[str] = set()
    for content in files.values():
        candidates.update(decode_candidates(str(content), check_types))
    if not candidates:
        return [
            finding(
                "warning",
                task_id,
                f"deterministic CTF check found no decodable flag candidate for: {', '.join(sorted(check_types))}",
            )
        ]
    normalized_candidates = {normalize_flag(candidate) for candidate in candidates}
    if expected_flags & normalized_candidates:
        return []
    preview = ", ".join(sorted(candidates)[:5])
    return [finding("error", task_id, f"decoded CTF candidates [{preview}] do not match expected flags.")]


def normalize_flag(flag: str) -> str:
    return re.sub(r"\s+", "", flag.strip())


def emit_result(result: dict[str, Any], args: argparse.Namespace) -> None:
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print_human_result(result)
    if args.report:
        report_path = PROJECT_ROOT / args.report
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(build_markdown_report(result), encoding="utf-8")
        print(f"Audit report: {report_path}")


def print_human_result(result: dict[str, Any]) -> None:
    stats = result.get("stats", {})
    print(f"Manifest audit: {'ok' if result.get('ok') else 'failed'}")
    print(f"Tasks: {stats.get('task_count', 0)}")
    for key in ["categories", "source_types", "licenses", "capabilities", "difficulties"]:
        print(f"{key}: {stats.get(key, {})}")
    print(f"Findings: errors={stats.get('error_count', 0)} warnings={stats.get('warning_count', 0)}")
    for item in result.get("findings", []):
        print(f"[{str(item.get('level')).upper()}] {item.get('target')}: {item.get('message')}")


def build_markdown_report(result: dict[str, Any]) -> str:
    stats = result.get("stats", {})
    lines = [
        "# Manifest 审计报告",
        "",
        f"- 状态：{'通过' if result.get('ok') else '失败'}",
        f"- 任务数：{stats.get('task_count', 0)}",
        f"- 错误：{stats.get('error_count', 0)}",
        f"- 警告：{stats.get('warning_count', 0)}",
        "",
        "## 分布",
        "",
    ]
    for key, label in [
        ("categories", "类别"),
        ("source_types", "来源类型"),
        ("licenses", "License"),
        ("capabilities", "能力桶"),
        ("difficulties", "难度"),
    ]:
        lines.append(f"- {label}: `{json.dumps(stats.get(key, {}), ensure_ascii=False)}`")
    lines.extend(["", "## 发现", ""])
    if not result.get("findings"):
        lines.append("未发现问题。")
    else:
        for item in result.get("findings", []):
            lines.append(f"- **{str(item.get('level')).upper()}** `{item.get('target')}`: {item.get('message')}")
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    raise SystemExit(main())
