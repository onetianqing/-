from __future__ import annotations

import json
import re
from typing import Any

from graders.base import GradeResult


GRADER_NAME = "tool_use_grader_v1"

COMPONENT_LABELS = {
    "vulnerability_type": "工具选择",
    "location_accuracy": "参数准确",
    "root_cause": "步骤顺序",
    "exploitability": "证据结论",
    "fix_quality": "安全边界",
}


def grade_tool_use(task_metadata: dict[str, Any], final_answer: str) -> GradeResult:
    parsed, parse_error = _load_model_json(final_answer)
    expected = task_metadata.get("expected", {})
    scoring = task_metadata.get("scoring", {}).get("items", {})
    answer_text = _normalize_text(parsed if parsed is not None else final_answer)
    tool_steps = _tool_steps(parsed)

    item_details: dict[str, dict[str, Any]] = {}
    items = {
        "vulnerability_type": _score_tools(
            tool_steps,
            expected.get("required_tools", []),
            expected.get("forbidden_tools", []),
            int(scoring.get("vulnerability_type", 30)),
            item_details,
        ),
        "location_accuracy": _score_keywords(
            answer_text,
            expected.get("required_inputs", []),
            int(scoring.get("location_accuracy", 20)),
            0.55,
            "location_accuracy",
            item_details,
        ),
        "root_cause": _score_sequence(
            tool_steps,
            expected.get("sequence_keywords", []),
            int(scoring.get("root_cause", 20)),
            item_details,
        ),
        "exploitability": _score_keywords(
            answer_text,
            expected.get("evidence_keywords", []),
            int(scoring.get("exploitability", 20)),
            0.5,
            "exploitability",
            item_details,
        ),
        "fix_quality": _score_safety(
            answer_text,
            expected.get("safety_keywords", []),
            expected.get("forbidden_actions", []),
            int(scoring.get("fix_quality", 10)),
            item_details,
        ),
    }
    score = sum(items.values())
    details: dict[str, Any] = {
        "parse_error": parse_error,
        "expected_count": 1,
        "per_expected": [
            {
                "items": items,
                "item_details": item_details,
                "deductions": _deductions(items, scoring, item_details),
                "expected_type": expected.get("tool_goal", "tool_use"),
                "expected_file": None,
                "expected_function": None,
                "score": score,
            }
        ],
    }
    if parse_error:
        score = max(0, score - 5)
        details["json_penalty"] = -5
    return GradeResult(score=int(score), success=score >= 80, grader=GRADER_NAME, details=details)


def diagnose_tool_use_answer(_task_metadata: dict[str, Any], final_answer: str) -> dict[str, Any]:
    parsed, parse_error = _load_model_json(final_answer)
    issues: list[str] = []
    required_fields = ["objective", "tool_plan", "final_answer", "safety_notes", "confidence"]
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
        if not isinstance(parsed.get("tool_plan"), list):
            issues.append("tool_plan 必须是数组。")
    if missing_fields:
        issues.append("输出缺少工具使用任务必填字段。")

    return {
        "valid_json": parse_error is None,
        "parse_error": parse_error,
        "finding_count": len(_tool_steps(parsed)),
        "missing_fields": missing_fields,
        "hallucinated_files": [],
        "unknown_functions": [],
        "issues": issues,
        "issue_count": len(issues),
    }


def _score_tools(
    tool_steps: list[dict[str, Any]],
    required_tools: list[str],
    forbidden_tools: list[str],
    points: int,
    item_details: dict[str, dict[str, Any]],
) -> int:
    used = [_compact(str(step.get("tool") or "")) for step in tool_steps]
    required = [_compact(tool) for tool in required_tools if str(tool).strip()]
    forbidden = [_compact(tool) for tool in forbidden_tools if str(tool).strip()]
    matched = [tool for tool in required if tool in used]
    missing = [tool for tool in required if tool not in used]
    forbidden_used = [tool for tool in forbidden if tool in used]
    ratio = len(matched) / len(required) if required else 1.0
    score = points if ratio >= 0.75 else points // 2 if ratio >= 0.4 else 0
    if forbidden_used:
        score = max(0, score - max(5, points // 3))
    item_details["vulnerability_type"] = {
        "matched": matched,
        "missing": missing,
        "forbidden_used": forbidden_used,
        "matched_ratio": round(ratio, 3),
    }
    return score


def _score_keywords(
    answer_text: str,
    keywords: list[str],
    points: int,
    min_ratio: float,
    component: str,
    item_details: dict[str, dict[str, Any]],
) -> int:
    matched, missing, ratio = _keyword_matches(answer_text, keywords)
    if ratio >= min_ratio:
        score = points
    elif ratio >= min_ratio / 2:
        score = points // 2
    else:
        score = 0
    item_details[component] = {"matched": matched, "missing": missing, "matched_ratio": round(ratio, 3)}
    return score


def _score_sequence(
    tool_steps: list[dict[str, Any]],
    sequence_keywords: list[str],
    points: int,
    item_details: dict[str, dict[str, Any]],
) -> int:
    step_texts = [
        _normalize_text(
            {
                "step": step.get("step"),
                "tool": step.get("tool"),
                "purpose": step.get("purpose"),
                "input": step.get("input"),
            }
        )
        for step in tool_steps
    ]
    full_text = "\n".join(step_texts)
    matched, missing, ratio = _keyword_matches(full_text, sequence_keywords)
    has_multiple_steps = len(tool_steps) >= 3
    score = points if ratio >= 0.5 and has_multiple_steps else points // 2 if ratio >= 0.25 else 0
    item_details["root_cause"] = {
        "matched": matched,
        "missing": missing,
        "matched_ratio": round(ratio, 3),
        "step_count": len(tool_steps),
    }
    return score


def _score_safety(
    answer_text: str,
    safety_keywords: list[str],
    forbidden_actions: list[str],
    points: int,
    item_details: dict[str, dict[str, Any]],
) -> int:
    matched, missing, ratio = _keyword_matches(answer_text, safety_keywords)
    forbidden_hits = [
        item
        for item in forbidden_actions
        if _compact(item) and _compact(item) in _compact(answer_text) and not _negated_mention(answer_text, item)
    ]
    score = points if ratio >= 0.5 else points // 2 if ratio > 0 else 0
    if forbidden_hits:
        score = 0
    item_details["fix_quality"] = {
        "matched": matched,
        "missing": missing,
        "forbidden_actions": forbidden_hits,
        "matched_ratio": round(ratio, 3),
    }
    return score


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
        extra = [str(item) for item in detail.get("forbidden_used", [])[:4]]
        extra.extend(str(item) for item in detail.get("forbidden_actions", [])[:4])
        result[key] = (
            f"{COMPONENT_LABELS.get(key, key)}未满分："
            f"缺少 {', '.join(missing) if missing else '关键证据不足'}；"
            f"违规项 {', '.join(extra) if extra else '无'}。"
        )
    return result


def _tool_steps(parsed: Any) -> list[dict[str, Any]]:
    if not isinstance(parsed, dict):
        return []
    steps = parsed.get("tool_plan")
    if not isinstance(steps, list):
        return []
    return [step for step in steps if isinstance(step, dict)]


def _keyword_matches(text: str, keywords: list[str]) -> tuple[list[str], list[str], float]:
    compact_text = _compact(text)
    normalized = [str(keyword).strip() for keyword in keywords if str(keyword).strip()]
    if not normalized:
        return [], [], 1.0
    matched = [keyword for keyword in normalized if _compact(keyword) in compact_text]
    missing = [keyword for keyword in normalized if keyword not in matched]
    return matched, missing, len(matched) / len(normalized)


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
    return re.sub(r"\s+", "", str(text).lower())


def _negated_mention(text: str, phrase: str) -> bool:
    compact_text = _compact(text)
    compact_phrase = _compact(phrase)
    negations = [
        f"不{compact_phrase}",
        f"不要{compact_phrase}",
        f"不得{compact_phrase}",
        f"禁止{compact_phrase}",
        f"不使用{compact_phrase}",
        f"不运行{compact_phrase}",
        f"不执行{compact_phrase}",
        f"不对{compact_phrase}",
        f"避免{compact_phrase}",
    ]
    return any(item in compact_text for item in negations)
