from __future__ import annotations

import json
import re
from typing import Any

from graders.base import GradeResult


GRADER_NAME = "audit_grader_v2"


TYPE_ALIASES = {
    "sql injection": ["sql injection", "sqli"],
    "cross-site scripting": ["cross-site scripting", "xss", "reflected xss", "stored xss"],
    "xss": ["xss", "cross-site scripting"],
    "ssrf": ["ssrf", "server-side request forgery"],
    "server-side request forgery": ["ssrf", "server-side request forgery"],
    "command injection": ["command injection", "os command injection", "shell injection"],
    "path traversal": ["path traversal", "directory traversal", "arbitrary file read"],
    "directory traversal": ["directory traversal", "path traversal", "arbitrary file read"],
}

EXPLOIT_MARKERS = [
    "exploit",
    "payload",
    "reproduce",
    "proof of concept",
    "poc",
    "attack",
    "bypass",
    "<script",
    "127.0.0.1",
    "localhost",
    "../",
    "..\\",
    ";",
    "&&",
    "' or",
    "1=1",
    "--",
]

FIX_MARKERS = {
    "sql injection": ["parameter", "prepared", "placeholder", "bind", "bound", "?"],
    "xss": ["escape", "encode", "sanitize", "template", "autoescape"],
    "cross-site scripting": ["escape", "encode", "sanitize", "template", "autoescape"],
    "ssrf": ["allowlist", "block", "validate url", "resolve", "private ip", "egress"],
    "server-side request forgery": ["allowlist", "block", "validate url", "resolve", "private ip", "egress"],
    "command injection": ["shell=false", "argument list", "subprocess", "validate", "allowlist"],
    "path traversal": ["resolve", "normalize", "safe directory", "base directory", "allowlist"],
    "directory traversal": ["resolve", "normalize", "safe directory", "base directory", "allowlist"],
}


def grade_audit(task_metadata: dict[str, Any], final_answer: str) -> GradeResult:
    expected_items = task_metadata.get("expected", {}).get("vulnerabilities", [])
    scoring = task_metadata.get("scoring", {}).get("items", {})
    total = int(task_metadata.get("scoring", {}).get("total", 100))
    parsed, parse_error = _load_model_json(final_answer)
    answer_text = _answer_to_text(parsed if parsed is not None else final_answer)

    if not expected_items:
        score = 100 if _looks_empty_finding(answer_text) else 40
        return GradeResult(score=score, success=score >= 80, grader=GRADER_NAME, details={"parse_error": parse_error})

    per_expected: list[dict[str, Any]] = []
    expected_scores: list[float] = []
    for expected in expected_items:
        item_score, item_details = _grade_expected_item(expected, scoring, parsed, answer_text)
        per_expected.append(item_details)
        expected_scores.append(item_score)

    score = sum(expected_scores) / len(expected_scores)
    if parse_error:
        score = max(0, score - 5)

    score = max(0, min(total, int(round(score))))
    details: dict[str, Any] = {
        "parse_error": parse_error,
        "expected_count": len(expected_items),
        "per_expected": per_expected,
    }
    if parse_error:
        details["json_penalty"] = -5
    return GradeResult(score=score, success=score >= 80, grader=GRADER_NAME, details=details)


def diagnose_audit_answer(task_metadata: dict[str, Any], final_answer: str) -> dict[str, Any]:
    parsed, parse_error = _load_model_json(final_answer)
    expected_files = {str(item).replace("\\", "/") for item in task_metadata.get("files", [])}
    expected_functions = {
        str(vuln.get("function"))
        for vuln in task_metadata.get("expected", {}).get("vulnerabilities", [])
        if vuln.get("function")
    }
    findings = []
    if isinstance(parsed, dict) and isinstance(parsed.get("findings"), list):
        findings = parsed.get("findings", [])

    issues: list[str] = []
    missing_fields: list[str] = []
    hallucinated_files: list[str] = []
    unknown_functions: list[str] = []
    required_fields = ["type", "severity", "file", "line", "function", "evidence", "root_cause", "exploit", "fix", "confidence"]

    if parse_error:
        issues.append("输出不是合法 JSON 或包含额外文本。")
    if parsed is not None and not isinstance(parsed, dict):
        issues.append("JSON 顶层不是对象。")
    if isinstance(parsed, dict) and "findings" not in parsed:
        issues.append("JSON 缺少 findings 字段。")
    if isinstance(parsed, dict) and "findings" in parsed and not isinstance(parsed.get("findings"), list):
        issues.append("findings 不是数组。")
    if not findings and not parse_error:
        issues.append("没有输出任何 finding。")

    for index, finding in enumerate(findings):
        if not isinstance(finding, dict):
            issues.append(f"finding[{index}] 不是对象。")
            continue
        for field in required_fields:
            value = finding.get(field)
            if field not in finding or value is None or value == "" or value == []:
                missing_fields.append(f"finding[{index}].{field}")
        file_value = str(finding.get("file") or "").replace("\\", "/")
        if file_value and expected_files and file_value not in expected_files and file_value.split("/")[-1] not in {f.split("/")[-1] for f in expected_files}:
            hallucinated_files.append(file_value)
        function_value = str(finding.get("function") or "")
        if function_value and expected_functions and function_value not in expected_functions:
            unknown_functions.append(function_value)

    if missing_fields:
        issues.append("部分 finding 缺少必填字段。")
    if hallucinated_files:
        issues.append("输出包含题目文件列表之外的文件名。")
    if unknown_functions:
        issues.append("输出包含标准答案之外的函数名。")

    return {
        "valid_json": parse_error is None,
        "parse_error": parse_error,
        "finding_count": len(findings),
        "missing_fields": missing_fields,
        "hallucinated_files": sorted(set(hallucinated_files)),
        "unknown_functions": sorted(set(unknown_functions)),
        "issues": issues,
        "issue_count": len(issues),
    }


def _grade_expected_item(
    expected: dict[str, Any],
    scoring: dict[str, Any],
    parsed: Any,
    answer_text: str,
) -> tuple[float, dict[str, Any]]:
    details: dict[str, Any] = {
        "items": {},
        "expected_type": expected.get("type"),
        "expected_file": expected.get("file"),
        "expected_function": expected.get("function"),
    }
    score = 0

    type_points = int(scoring.get("vulnerability_type", 20))
    type_score = type_points if _matches_vuln_type(answer_text, str(expected.get("type", ""))) else 0
    details["items"]["vulnerability_type"] = type_score
    score += type_score

    location_points = int(scoring.get("location_accuracy", 20))
    location_score = _score_location(answer_text, parsed, expected, location_points)
    details["items"]["location_accuracy"] = location_score
    score += location_score

    root_points = int(scoring.get("root_cause", 20))
    root_score = _score_root_cause(answer_text, expected, root_points)
    details["items"]["root_cause"] = root_score
    score += root_score

    exploit_points = int(scoring.get("exploitability", 25))
    exploit_score = _score_exploitability(answer_text, exploit_points)
    details["items"]["exploitability"] = exploit_score
    score += exploit_score

    fix_points = int(scoring.get("fix_quality", 15))
    fix_score = _score_fix(answer_text, str(expected.get("type", "")), fix_points)
    details["items"]["fix_quality"] = fix_score
    score += fix_score

    details["score"] = score
    return float(score), details


def _load_model_json(text: str) -> tuple[Any | None, str | None]:
    stripped = text.strip()
    if stripped.startswith("```"):
        stripped = re.sub(r"^```(?:json)?\s*", "", stripped)
        stripped = re.sub(r"\s*```$", "", stripped)
    try:
        return json.loads(stripped), None
    except json.JSONDecodeError as exc:
        return None, str(exc)


def _answer_to_text(answer: Any) -> str:
    if isinstance(answer, str):
        return answer.lower()
    return json.dumps(answer, ensure_ascii=False).lower()


def _matches_vuln_type(answer_text: str, expected_type: str) -> bool:
    normalized = expected_type.strip().lower()
    aliases = TYPE_ALIASES.get(normalized, [normalized])
    return any(alias in answer_text for alias in aliases)


def _score_location(answer_text: str, parsed: Any, expected: dict[str, Any], points: int) -> int:
    score = 0
    expected_file = str(expected.get("file", "")).lower()
    expected_function = str(expected.get("function", "")).lower()
    if expected_file and (expected_file in answer_text or expected_file.split("/")[-1] in answer_text):
        score += points // 2
    if expected_function and expected_function in answer_text:
        score += points // 4
    line_hint = expected.get("line_hint")
    if line_hint is not None and _contains_nearby_line(parsed, int(line_hint), tolerance=5):
        score += points - score
    return min(points, score)


def _contains_nearby_line(parsed: Any, expected_line: int, tolerance: int) -> bool:
    lines: list[int] = []

    def collect(value: Any) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                if str(key).lower() in {"line", "line_hint", "lineno", "line_number"}:
                    try:
                        lines.append(int(child))
                    except (TypeError, ValueError):
                        pass
                collect(child)
        elif isinstance(value, list):
            for child in value:
                collect(child)

    collect(parsed)
    return any(abs(line - expected_line) <= tolerance for line in lines)


def _score_root_cause(answer_text: str, expected: dict[str, Any], points: int) -> int:
    explicit_keywords = expected.get("keywords", [])
    if explicit_keywords:
        return _score_keyword_list(answer_text, explicit_keywords, points, min_ratio=0.45)
    return _score_keywords(answer_text, str(expected.get("root_cause", "")), points, min_ratio=0.28)


def _score_keywords(answer_text: str, expected_text: str, points: int, min_ratio: float) -> int:
    words = [
        word.lower()
        for word in re.findall(r"[a-zA-Z0-9_.'/-]+", expected_text)
        if len(word) > 3 and word.lower() not in {"into", "with", "from", "that", "this", "user", "input"}
    ]
    return _score_keyword_list(answer_text, words, points, min_ratio)


def _score_keyword_list(answer_text: str, keywords: list[str], points: int, min_ratio: float) -> int:
    normalized = [str(keyword).lower() for keyword in keywords if str(keyword).strip()]
    if not normalized:
        return 0
    matched = sum(1 for keyword in normalized if keyword in answer_text)
    ratio = matched / len(normalized)
    if ratio >= min_ratio:
        return points
    if ratio >= min_ratio / 2:
        return points // 2
    return 0


def _score_exploitability(answer_text: str, points: int) -> int:
    matched = sum(1 for marker in EXPLOIT_MARKERS if marker in answer_text)
    if matched >= 3:
        return points
    if matched >= 1:
        return points // 2
    return 0


def _score_fix(answer_text: str, expected_type: str, points: int) -> int:
    normalized = expected_type.strip().lower()
    aliases = [normalized] + TYPE_ALIASES.get(normalized, [])
    markers: list[str] = ["fix", "escape", "sanitize", "validate", "allowlist"]
    for alias in aliases:
        markers.extend(FIX_MARKERS.get(alias, []))
    if any(marker in answer_text for marker in markers):
        return points
    return 0


def _looks_empty_finding(answer_text: str) -> bool:
    return any(marker in answer_text for marker in ["no finding", "no vulnerability", "no issue", "none found"])
