from __future__ import annotations

import json
import re
from typing import Any

from graders.base import GradeResult


GRADER_NAME = "log_grader_v1"


def grade_log_analysis(task_metadata: dict[str, Any], final_answer: str) -> GradeResult:
    parsed, parse_error = _load_model_json(final_answer)
    answer_text = _answer_to_text(parsed if parsed is not None else final_answer)
    expected = task_metadata.get("expected", {})
    scoring = task_metadata.get("scoring", {}).get("items", {})

    items = {
        "vulnerability_type": _score_keywords(answer_text, expected.get("attack_type_keywords", []), int(scoring.get("vulnerability_type", 20)), 0.5),
        "location_accuracy": _score_keywords(answer_text, expected.get("evidence_keywords", []), int(scoring.get("location_accuracy", 25)), 0.45),
        "root_cause": _score_keywords(answer_text, expected.get("timeline_keywords", []), int(scoring.get("root_cause", 20)), 0.45),
        "exploitability": _score_keywords(answer_text, expected.get("impact_keywords", []), int(scoring.get("exploitability", 15)), 0.45),
        "fix_quality": _score_keywords(answer_text, expected.get("remediation_keywords", []), int(scoring.get("fix_quality", 20)), 0.45),
    }
    score = sum(items.values())
    details: dict[str, Any] = {
        "parse_error": parse_error,
        "expected_count": 1,
        "per_expected": [
            {
                "items": items,
                "expected_type": expected.get("attack_type"),
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


def diagnose_log_answer(_task_metadata: dict[str, Any], final_answer: str) -> dict[str, Any]:
    parsed, parse_error = _load_model_json(final_answer)
    issues: list[str] = []
    required_fields = ["attack_type", "evidence", "timeline", "impact", "remediation", "confidence"]
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
        issues.append("输出缺少日志分析必填字段。")
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


def _score_keywords(answer_text: str, keywords: list[str], points: int, min_ratio: float) -> int:
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
