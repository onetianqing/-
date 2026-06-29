from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from runners.benchmark import DIFFICULTY_WEIGHTS
from runners.config_loader import load_yaml
from runners.ctf_consistency import validate_ctf_artifact_consistency


SUPPORTED_CATEGORIES = {"audit", "log_analysis", "patch", "ctf", "tool_use"}
REQUIRED_METADATA_FIELDS = [
    "id",
    "title",
    "category",
    "sub_category",
    "difficulty",
    "language",
    "tags",
    "prompt_file",
    "files",
    "expected",
    "scoring",
    "execution",
]
REQUIRED_SOURCE_FIELDS = ["type", "origin", "license"]
REQUIRED_SCORING_ITEMS = ["vulnerability_type", "location_accuracy", "root_cause", "exploitability", "fix_quality"]
REQUIRED_MODEL_FIELDS = ["name", "enabled", "provider", "model_id", "max_tokens", "temperature"]
REQUIRED_LOG_EXPECTED_FIELDS = [
    "attack_type",
    "attack_type_keywords",
    "evidence_keywords",
    "timeline_keywords",
    "impact_keywords",
    "remediation_keywords",
]
REQUIRED_PATCH_EXPECTED_FIELDS = [
    "vulnerability_type",
    "vulnerability_keywords",
    "location_keywords",
    "root_cause_keywords",
    "fix_keywords",
    "test_keywords",
]
REQUIRED_CTF_EXPECTED_FIELDS = [
    "flag",
    "flag_type",
    "flag_format",
    "evidence_keywords",
    "method_keywords",
    "reproduction_keywords",
]
REQUIRED_TOOL_USE_EXPECTED_FIELDS = [
    "tool_goal",
    "required_tools",
    "forbidden_tools",
    "required_inputs",
    "sequence_keywords",
    "evidence_keywords",
    "safety_keywords",
]


def main() -> int:
    args = parse_args()
    findings: list[dict[str, Any]] = []
    if args.scope in {"all", "tasks"}:
        findings.extend(validate_tasks(args.category))
    if args.scope in {"all", "models"}:
        findings.extend(validate_models())

    if args.json:
        print(json.dumps({"ok": not has_errors(findings), "findings": findings}, ensure_ascii=False, indent=2))
    else:
        print_human(findings)
    return 1 if has_errors(findings) else 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate platform configuration and task metadata.")
    parser.add_argument("--scope", choices=["all", "tasks", "models"], default="all")
    parser.add_argument("--category", default="audit", help="Task category, for example audit, log_analysis, patch, ctf or tool_use.")
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON.")
    return parser.parse_args()


def validate_tasks(category: str) -> list[dict[str, Any]]:
    if category not in SUPPORTED_CATEGORIES:
        return [finding("error", "tasks", f"不支持的任务类别：{category}。支持：{', '.join(sorted(SUPPORTED_CATEGORIES))}")]

    task_root = PROJECT_ROOT / "tasks" / category
    findings: list[dict[str, Any]] = []
    if not task_root.exists():
        return [finding("error", "tasks", f"任务目录不存在：{task_root}")]

    ids: dict[str, Path] = {}
    for metadata_path in sorted(task_root.glob("*/metadata.json")):
        task_dir = metadata_path.parent
        try:
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            findings.append(finding("error", str(metadata_path), f"metadata.json 不是合法 JSON：{exc}"))
            continue

        task_id = str(metadata.get("id") or task_dir.name)
        if task_id in ids:
            findings.append(finding("error", task_id, f"任务 ID 重复，已出现于 {ids[task_id]}"))
        ids[task_id] = metadata_path
        findings.extend(validate_task_metadata(task_dir, metadata, category))

    if not ids:
        findings.append(finding("warning", "tasks", f"没有发现 {category} 任务。"))
    return findings


def validate_task_metadata(task_dir: Path, metadata: dict[str, Any], selected_category: str) -> list[dict[str, Any]]:
    task_id = str(metadata.get("id") or task_dir.name)
    findings: list[dict[str, Any]] = []

    for field in REQUIRED_METADATA_FIELDS:
        if field not in metadata:
            findings.append(finding("error", task_id, f"metadata 缺少字段：{field}"))

    category = str(metadata.get("category") or "")
    if category not in SUPPORTED_CATEGORIES:
        findings.append(finding("error", task_id, f"不支持的任务类别：{category}"))
    elif category != selected_category:
        findings.append(finding("warning", task_id, f"metadata.category={category} 与当前校验类别 {selected_category} 不一致。"))

    prompt_file = metadata.get("prompt_file")
    if prompt_file and not (task_dir / str(prompt_file)).exists():
        findings.append(finding("error", task_id, f"prompt_file 不存在：{prompt_file}"))

    files = metadata.get("files", [])
    if not isinstance(files, list) or not files:
        findings.append(finding("error", task_id, "files 必须是非空数组。"))
    else:
        for relative in files:
            if not (task_dir / str(relative)).exists():
                findings.append(finding("error", task_id, f"题目文件不存在：{relative}"))

    findings.extend(validate_source(task_id, metadata))

    expected = metadata.get("expected", {})
    if not isinstance(expected, dict):
        findings.append(finding("error", task_id, "expected 必须是对象。"))
    elif category == "log_analysis":
        findings.extend(validate_log_expected(task_id, expected))
    elif category == "patch":
        findings.extend(validate_patch_expected(task_id, expected))
    elif category == "ctf":
        findings.extend(validate_ctf_expected(task_id, expected))
        findings.extend(validate_ctf_artifact_consistency(task_dir, metadata))
    elif category == "tool_use":
        findings.extend(validate_tool_use_expected(task_id, expected))
    else:
        findings.extend(validate_audit_expected(task_id, expected, files))

    findings.extend(validate_scoring(task_id, metadata))
    findings.extend(validate_benchmark(task_id, metadata))
    return findings


def validate_source(task_id: str, metadata: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    source = metadata.get("source")
    if not isinstance(source, dict):
        return [finding("warning", task_id, "建议补充 source 来源字段。")]

    for field in REQUIRED_SOURCE_FIELDS:
        if not source.get(field):
            findings.append(finding("warning", task_id, f"source 缺少字段：{field}"))
    if source.get("type") != "synthetic" and not source.get("reference_url"):
        findings.append(finding("warning", task_id, "公开来源、业务代码或 CVE 题建议提供 source.reference_url。"))
    if source.get("type") == "synthetic":
        findings.append(finding("warning", task_id, "当前题目为 synthetic，主线题库建议优先使用公开 CTF、真实业务代码或 CVE 改写样例。"))
    return findings


def validate_audit_expected(task_id: str, expected: dict[str, Any], files: list[Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    vulnerabilities = expected.get("vulnerabilities")
    if not isinstance(vulnerabilities, list) or not vulnerabilities:
        return [finding("error", task_id, "expected.vulnerabilities 必须是非空数组。")]

    for index, vuln in enumerate(vulnerabilities):
        for field in ["type", "file", "function", "root_cause"]:
            if not isinstance(vuln, dict) or not vuln.get(field):
                findings.append(finding("error", task_id, f"expected.vulnerabilities[{index}] 缺少字段：{field}"))
        file_value = str(vuln.get("file", ""))
        if file_value and files and file_value not in files:
            findings.append(finding("warning", task_id, f"标准答案文件不在 files 列表中：{file_value}"))
    return findings


def validate_log_expected(task_id: str, expected: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for field in REQUIRED_LOG_EXPECTED_FIELDS:
        value = expected.get(field)
        if field.endswith("_keywords"):
            if not isinstance(value, list) or not value:
                findings.append(finding("error", task_id, f"expected.{field} 必须是非空数组。"))
        elif not value:
            findings.append(finding("error", task_id, f"expected.{field} 不能为空。"))
    return findings


def validate_patch_expected(task_id: str, expected: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for field in REQUIRED_PATCH_EXPECTED_FIELDS:
        value = expected.get(field)
        if field.endswith("_keywords"):
            if not isinstance(value, list) or not value:
                findings.append(finding("error", task_id, f"expected.{field} must be a non-empty list."))
        elif not value:
            findings.append(finding("error", task_id, f"expected.{field} cannot be empty."))
    return findings


def validate_ctf_expected(task_id: str, expected: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for field in REQUIRED_CTF_EXPECTED_FIELDS:
        value = expected.get(field)
        if field.endswith("_keywords"):
            if not isinstance(value, list) or not value:
                findings.append(finding("error", task_id, f"expected.{field} must be a non-empty list."))
        elif not value:
            findings.append(finding("error", task_id, f"expected.{field} cannot be empty."))
    flag = str(expected.get("flag") or "")
    flag_format = str(expected.get("flag_format") or "")
    accepted_flags = expected.get("accepted_flags", [])
    if flag and "{" not in flag:
        findings.append(finding("warning", task_id, "expected.flag does not look like a standard CTF flag."))
    if flag_format and "{" not in flag_format:
        findings.append(finding("warning", task_id, "expected.flag_format does not describe a brace-style flag."))
    if accepted_flags:
        if not isinstance(accepted_flags, list):
            findings.append(finding("error", task_id, "expected.accepted_flags must be a list when provided."))
        else:
            for idx, accepted_flag in enumerate(accepted_flags):
                accepted_flag_text = str(accepted_flag or "").strip()
                if not accepted_flag_text:
                    findings.append(finding("error", task_id, f"expected.accepted_flags[{idx}] cannot be empty."))
                elif flag and accepted_flag_text == flag:
                    findings.append(finding("warning", task_id, f"expected.accepted_flags[{idx}] duplicates expected.flag."))
                elif "{" not in accepted_flag_text:
                    findings.append(finding("warning", task_id, f"expected.accepted_flags[{idx}] does not look like a standard CTF flag."))
    return findings


def validate_tool_use_expected(task_id: str, expected: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for field in REQUIRED_TOOL_USE_EXPECTED_FIELDS:
        value = expected.get(field)
        if field == "tool_goal":
            if not value:
                findings.append(finding("error", task_id, "expected.tool_goal cannot be empty."))
        elif not isinstance(value, list) or not value:
            findings.append(finding("error", task_id, f"expected.{field} must be a non-empty list."))
    required_tools = {str(item).strip() for item in expected.get("required_tools", []) if str(item).strip()}
    forbidden_tools = {str(item).strip() for item in expected.get("forbidden_tools", []) if str(item).strip()}
    overlap = required_tools & forbidden_tools
    if overlap:
        findings.append(finding("error", task_id, f"required_tools and forbidden_tools overlap: {', '.join(sorted(overlap))}"))
    return findings


def validate_scoring(task_id: str, metadata: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    scoring = metadata.get("scoring", {})
    items = scoring.get("items") if isinstance(scoring, dict) else None
    if not isinstance(items, dict):
        return [finding("error", task_id, "scoring.items 必须是对象。")]

    item_sum = 0
    for field in REQUIRED_SCORING_ITEMS:
        value = items.get(field)
        if not isinstance(value, int):
            findings.append(finding("error", task_id, f"scoring.items.{field} 必须是整数。"))
        else:
            item_sum += value
    total = scoring.get("total", 100)
    if isinstance(total, int) and item_sum != total:
        findings.append(finding("warning", task_id, f"评分项总和 {item_sum} 与 scoring.total {total} 不一致。"))
    return findings


def validate_benchmark(task_id: str, metadata: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    benchmark = metadata.get("benchmark")
    if benchmark is None:
        return [finding("warning", task_id, "metadata 建议补充 benchmark 字段，用于大规模题库的加权汇总。")]
    if not isinstance(benchmark, dict):
        return [finding("error", task_id, "benchmark 必须是对象。")]
    if not benchmark.get("suite"):
        findings.append(finding("warning", task_id, "benchmark.suite 为空，将使用默认 suite。"))
    if not benchmark.get("capability"):
        findings.append(finding("warning", task_id, "benchmark.capability 为空，将使用 sub_category 作为能力桶。"))
    for field in ["weight", "difficulty_weight", "capability_weight"]:
        if field not in benchmark:
            continue
        try:
            value = float(benchmark.get(field))
        except (TypeError, ValueError):
            findings.append(finding("error", task_id, f"benchmark.{field} 必须是数字。"))
            continue
        if value <= 0:
            findings.append(finding("error", task_id, f"benchmark.{field} 必须大于 0。"))
    difficulty = str(metadata.get("difficulty") or "").lower()
    if difficulty and difficulty not in DIFFICULTY_WEIGHTS and "difficulty_weight" not in benchmark:
        findings.append(finding("warning", task_id, f"difficulty={difficulty} 没有默认权重，建议显式设置 benchmark.difficulty_weight。"))
    return findings


def validate_models(api_key_check_names: set[str] | None = None) -> list[dict[str, Any]]:
    path = PROJECT_ROOT / "config" / "models.yaml"
    findings: list[dict[str, Any]] = []
    if not path.exists():
        return [finding("error", "models", f"模型配置不存在：{path}")]

    config = load_yaml(path)
    models = config.get("models", [])
    if not isinstance(models, list) or not models:
        return [finding("error", "models", "models.yaml 中没有 models 列表。")]

    names: set[str] = set()
    for model in models:
        name = str(model.get("name") or "")
        if not name:
            findings.append(finding("error", "models", "存在未命名模型。"))
            continue
        if name in names:
            findings.append(finding("error", name, "模型名称重复。"))
        names.add(name)
        for field in REQUIRED_MODEL_FIELDS:
            if field not in model:
                findings.append(finding("warning", name, f"模型配置缺少字段：{field}"))
        provider = model.get("provider")
        if provider == "openai_compatible":
            if not model.get("base_url"):
                findings.append(finding("error", name, "openai_compatible 模型缺少 base_url。"))
            api_key_env = str(model.get("api_key_env") or "")
            if not api_key_env:
                findings.append(finding("error", name, "openai_compatible 模型缺少 api_key_env。"))
            elif model.get("enabled", True) and not os.environ.get(api_key_env) and (
                api_key_check_names is None or name in api_key_check_names
            ):
                findings.append(finding("warning", name, f"模型已启用，但环境变量未设置：{api_key_env}"))
        elif provider != "local_mock":
            findings.append(finding("warning", name, f"未知 provider：{provider}"))

        for price_field in [
            "usd_per_1m_input_tokens",
            "usd_per_1m_output_tokens",
            "rmb_per_1m_input_tokens",
            "rmb_per_1m_output_tokens",
        ]:
            if price_field in model:
                try:
                    float(model.get(price_field) or 0)
                except (TypeError, ValueError):
                    findings.append(finding("warning", name, f"{price_field} 不是数字。"))

    return findings


def finding(level: str, target: str, message: str) -> dict[str, str]:
    return {"level": level, "target": target, "message": message}


def has_errors(findings: list[dict[str, Any]]) -> bool:
    return any(item.get("level") == "error" for item in findings)


def print_human(findings: list[dict[str, Any]]) -> None:
    if not findings:
        print("自检通过：没有发现错误或警告。")
        return
    errors = sum(1 for item in findings if item.get("level") == "error")
    warnings = sum(1 for item in findings if item.get("level") == "warning")
    print(f"自检完成：{errors} 个错误，{warnings} 个警告。")
    for item in findings:
        marker = "ERROR" if item.get("level") == "error" else "WARN"
        print(f"[{marker}] {item.get('target')}: {item.get('message')}")


if __name__ == "__main__":
    raise SystemExit(main())
