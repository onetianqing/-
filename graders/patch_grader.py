from __future__ import annotations

import json
import re
from typing import Any

from graders.base import GradeResult


GRADER_NAME = "patch_grader_v2"

COMPONENT_LABELS = {
    "vulnerability_type": "类型判断",
    "location_accuracy": "关键证据/定位",
    "root_cause": "根因/时间线",
    "exploitability": "复现/影响判断",
    "fix_quality": "修复/处置建议",
}

VULNERABILITY_ALIASES = {
    "sql injection": ["sql injection", "sqli", "sql注入", "sql 注入", "注入漏洞", "数据库注入"],
    "cross-site scripting": ["cross-site scripting", "xss", "跨站脚本", "脚本注入"],
    "command injection": ["command injection", "命令注入", "命令执行", "shell注入"],
    "path traversal": ["path traversal", "directory traversal", "路径穿越", "目录穿越", "../"],
    "ssrf": ["ssrf", "server-side request forgery", "服务端请求伪造"],
}

CONCEPT_ALIASES = {
    "sql": ["sql"],
    "injection": ["injection", "注入"],
    "sqli": ["sqli", "sql注入", "sql 注入"],
    "user input": ["user input", "用户输入", "用户可控", "外部输入", "不可信输入"],
    "untrusted": ["untrusted", "不可信", "用户可控", "未受信任"],
    "concatenate": ["concatenate", "concatenated", "拼接", "字符串拼接", "动态拼接"],
    "string concatenation": ["string concatenation", "字符串拼接", "拼接"],
    "parameter": ["parameter", "参数", "参数化", "参数化处理", "参数绑定"],
    "parameterized": ["parameterized", "parameterised", "参数化", "参数化查询", "参数绑定"],
    "placeholder": ["placeholder", "占位符", "?"],
    "bind": ["bind", "binding", "绑定", "参数绑定", "[email, password]"],
    "prepared": ["prepared", "prepared statement", "预编译", "预处理"],
    "unit test": ["unit test", "单元测试", "测试用例", "用例"],
    "malicious": ["malicious", "恶意", "攻击", "payload"],
    "' or '1'='1": ["' or '1'='1", "' or 1=1", "or 1=1", "1=1", "绕过认证"],
    "normal login": ["normal login", "正常登录", "合法", "正确"],
    "regression": ["regression", "回归", "回归测试"],
}


def grade_patch(task_metadata: dict[str, Any], final_answer: str) -> GradeResult:
    parsed, parse_error = _load_model_json(final_answer)
    answer_text = _normalize_text(parsed if parsed is not None else final_answer)
    expected = task_metadata.get("expected", {})
    scoring = task_metadata.get("scoring", {}).get("items", {})

    item_details: dict[str, dict[str, Any]] = {}
    items = {
        "vulnerability_type": _score_vulnerability_type(
            parsed,
            answer_text,
            expected,
            int(scoring.get("vulnerability_type", 20)),
            item_details,
        ),
        "location_accuracy": _score_component(
            answer_text,
            expected.get("location_keywords", []),
            int(scoring.get("location_accuracy", 15)),
            0.45,
            "location_accuracy",
            item_details,
        ),
        "root_cause": _score_component(
            answer_text,
            expected.get("root_cause_keywords", []),
            int(scoring.get("root_cause", 20)),
            0.45,
            "root_cause",
            item_details,
        ),
        "exploitability": _score_component(
            answer_text,
            expected.get("test_keywords", []) + expected.get("verification_keywords", []),
            int(scoring.get("exploitability", 20)),
            0.4,
            "exploitability",
            item_details,
        ),
        "fix_quality": _score_component(
            answer_text,
            expected.get("fix_keywords", []),
            int(scoring.get("fix_quality", 25)),
            0.45,
            "fix_quality",
            item_details,
        ),
    }
    score = sum(items.values())
    deductions = _deductions(items, scoring, item_details)
    details: dict[str, Any] = {
        "parse_error": parse_error,
        "expected_count": 1,
        "per_expected": [
            {
                "items": items,
                "item_details": item_details,
                "deductions": deductions,
                "expected_type": expected.get("vulnerability_type"),
                "expected_file": expected.get("file"),
                "expected_function": expected.get("function"),
                "score": score,
            }
        ],
    }
    if parse_error:
        score = max(0, score - 5)
        details["json_penalty"] = -5
    return GradeResult(score=int(score), success=score >= 80, grader=GRADER_NAME, details=details)


def diagnose_patch_answer(_task_metadata: dict[str, Any], final_answer: str) -> dict[str, Any]:
    parsed, parse_error = _load_model_json(final_answer)
    issues: list[str] = []
    required_fields = ["vulnerability", "root_cause", "patch", "tests", "impact", "confidence"]
    missing_fields: list[str] = []

    if parse_error:
        issues.append("输出不是合法 JSON 或包含额外文本。")
    if parsed is not None and not isinstance(parsed, dict):
        issues.append("JSON 顶层不是对象。")
    if isinstance(parsed, dict):
        for field in required_fields:
            value = parsed.get(field)
            if field not in parsed or value is None or value == "" or value == []:
                missing_fields.append(field)
    if missing_fields:
        issues.append("输出缺少安全修复必填字段。")

    return {
        "valid_json": parse_error is None,
        "parse_error": parse_error,
        "finding_count": 1 if isinstance(parsed, dict) and not parse_error else 0,
        "missing_fields": missing_fields,
        "hallucinated_files": [],
        "unknown_functions": [],
        "issues": issues,
        "issue_count": len(issues),
    }


def _score_vulnerability_type(
    parsed: Any,
    answer_text: str,
    expected: dict[str, Any],
    points: int,
    item_details: dict[str, dict[str, Any]],
) -> int:
    expected_type = str(expected.get("vulnerability_type") or "")
    keywords = expected.get("vulnerability_keywords", []) + [expected_type]
    if expected_type.lower() == "sql injection":
        keywords = keywords + ["sql注入", "sql 注入", "注入漏洞"]

    field_text = ""
    if isinstance(parsed, dict):
        field_text = _normalize_text(parsed.get("vulnerability", ""))
    score, detail = _concept_score(field_text or answer_text, keywords, points, 0.35)
    if score < points and field_text and _contains_alias(field_text, _aliases_for_vulnerability(expected_type)):
        score = points
        detail["matched"].append(expected_type)
        detail["missing"] = []
    item_details["vulnerability_type"] = detail
    return score


def _score_component(
    answer_text: str,
    keywords: list[str],
    points: int,
    min_ratio: float,
    component: str,
    item_details: dict[str, dict[str, Any]],
) -> int:
    score, detail = _concept_score(answer_text, keywords, points, min_ratio)
    item_details[component] = detail
    return score


def _concept_score(text: str, keywords: list[str], points: int, min_ratio: float) -> tuple[int, dict[str, Any]]:
    concepts = _expand_concepts(keywords)
    if not concepts:
        return 0, {"matched": [], "missing": [], "matched_ratio": 0.0}

    matched: list[str] = []
    missing: list[str] = []
    for canonical, aliases in concepts:
        if _contains_alias(text, aliases):
            matched.append(canonical)
        else:
            missing.append(canonical)
    ratio = len(matched) / len(concepts)
    if ratio >= min_ratio:
        score = points
    elif ratio >= min_ratio / 2:
        score = points // 2
    else:
        score = 0
    return score, {"matched": matched, "missing": missing, "matched_ratio": round(ratio, 3)}


def _expand_concepts(keywords: list[str]) -> list[tuple[str, list[str]]]:
    concepts: list[tuple[str, list[str]]] = []
    seen: set[str] = set()
    for keyword in keywords:
        canonical = str(keyword).strip().lower()
        if not canonical or canonical in seen:
            continue
        aliases = [canonical]
        aliases.extend(CONCEPT_ALIASES.get(canonical, []))
        aliases.extend(_aliases_for_vulnerability(canonical))
        concepts.append((canonical, aliases))
        seen.add(canonical)
    return concepts


def _aliases_for_vulnerability(value: str) -> list[str]:
    normalized = value.strip().lower()
    if normalized in VULNERABILITY_ALIASES:
        return VULNERABILITY_ALIASES[normalized]
    for canonical, aliases in VULNERABILITY_ALIASES.items():
        if normalized == canonical or normalized in aliases:
            return aliases
    return []


def _contains_alias(text: str, aliases: list[str]) -> bool:
    compact_text = _compact(text)
    for alias in aliases:
        normalized = str(alias).strip().lower()
        if not normalized:
            continue
        if normalized in text or _compact(normalized) in compact_text:
            return True
    return False


def _deductions(
    items: dict[str, int],
    scoring: dict[str, Any],
    item_details: dict[str, dict[str, Any]],
) -> dict[str, str]:
    result: dict[str, str] = {}
    for key, score in items.items():
        max_points = int(scoring.get(key, score) or 0)
        if score >= max_points:
            continue
        detail = item_details.get(key, {})
        missing = [str(item) for item in detail.get("missing", [])[:4]]
        matched = [str(item) for item in detail.get("matched", [])[:4]]
        result[key] = (
            f"{COMPONENT_LABELS.get(key, key)}未满分："
            f"已命中 {', '.join(matched) if matched else '无'}；"
            f"仍缺少 {', '.join(missing) if missing else '评分证据不足'}。"
        )
    return result


def _load_model_json(text: str) -> tuple[Any | None, str | None]:
    stripped = text.strip()
    if stripped.startswith("```"):
        stripped = re.sub(r"^```(?:json)?\s*", "", stripped)
        stripped = re.sub(r"\s*```$", "", stripped)
    try:
        return json.loads(stripped), None
    except json.JSONDecodeError as exc:
        return None, str(exc)


def _normalize_text(answer: Any) -> str:
    if isinstance(answer, str):
        return answer.lower()
    return json.dumps(answer, ensure_ascii=False).lower()


def _compact(text: str) -> str:
    return re.sub(r"\s+", "", text.lower())
