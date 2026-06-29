from __future__ import annotations

import argparse
import html
import json
import sys
from collections import defaultdict
from pathlib import Path
from statistics import mean, stdev
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from runners.benchmark import (
    benchmark_score,
    benchmark_solve_rate,
    capability_stats,
    difficulty_stats,
    enrich_row as enrich_benchmark_row,
    total_effective_weight,
)
from runners.config_loader import load_yaml
from runners.task_index import load_task_metadata_map

COMPONENTS = [
    ("vulnerability_type", "类型判断", 20, "#2a7f62"),
    ("location_accuracy", "关键证据/定位", 20, "#3f6fb5"),
    ("root_cause", "根因/时间线", 20, "#b7791f"),
    ("exploitability", "复现/影响判断", 25, "#8a5fbf"),
    ("fix_quality", "修复/处置建议", 15, "#c55353"),
]

MODEL_COLORS = [
    "#2563eb",
    "#16a34a",
    "#dc2626",
    "#9333ea",
    "#d97706",
    "#0891b2",
    "#be123c",
    "#4d7c0f",
]

DEDUCTION_REASONS = {
    "vulnerability_type": "没有准确识别任务要求的攻击/风险类型，或缺少关键别名。",
    "location_accuracy": "关键证据、位置、文件、函数、IP、时间戳或日志字段覆盖不足。",
    "root_cause": "根因、攻击链或事件时间线解释不完整，缺少关键数据流或行为连接。",
    "exploitability": "复现路径、利用条件、影响范围或事件后果说明不够明确。",
    "fix_quality": "修复、加固或应急处置建议缺少关键措施，难以直接阻断风险。",
}

CATEGORY_COMPONENT_LABELS = {
    "tool_use": {
        "vulnerability_type": "工具选择",
        "location_accuracy": "参数准确",
        "root_cause": "步骤顺序",
        "exploitability": "证据结论",
        "fix_quality": "安全边界",
    }
}


def main() -> int:
    args = parse_args()
    if args.index:
        output_path = generate_index()
        print(f"Report index written: {output_path}")
        return 0

    run_ids = selected_run_ids(args)
    output_id = args.output_id or "-vs-".join(run_ids)
    rows: list[dict[str, Any]] = []
    for run_id in run_ids:
        scored_path = PROJECT_ROOT / "results" / "scored" / f"{run_id}.jsonl"
        if not scored_path.exists():
            print(f"Scored file not found: {scored_path}", file=sys.stderr)
            return 2
        rows.extend(load_scored_rows(scored_path, run_id))

    rows = enrich_rows(rows)
    output_dir = PROJECT_ROOT / "results" / "reports"
    output_dir.mkdir(parents=True, exist_ok=True)

    md_path = output_dir / f"{output_id}.md"
    md_path.write_text(build_markdown_report(output_id, rows, run_ids), encoding="utf-8")
    print(f"Markdown report written: {md_path}")

    if not args.no_html:
        html_path = output_dir / f"{output_id}.html"
        html_path.write_text(build_html_report(output_id, rows, run_ids), encoding="utf-8")
        print(f"HTML report written: {html_path}")
    return 0


def selected_run_ids(args: argparse.Namespace) -> list[str]:
    if args.run_ids:
        run_ids = [item.strip() for item in args.run_ids.split(",") if item.strip()]
        if not run_ids:
            raise SystemExit("No valid run ids in --run-ids.")
        return run_ids
    run_id = args.run_id
    if args.latest:
        run_id = find_latest_run_id()
    if not run_id:
        raise SystemExit("Provide --run-id, --run-ids, --latest, or --index.")
    return [run_id]


def load_scored_rows(scored_path: Path, fallback_run_id: str) -> list[dict[str, Any]]:
    rows = []
    for line in scored_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        row.setdefault("run_id", fallback_run_id)
        rows.append(row)
    return rows


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate evaluation report.")
    parser.add_argument("--run-id", default=None)
    parser.add_argument("--run-ids", default=None, help="Comma-separated run ids to merge into one report.")
    parser.add_argument("--output-id", default=None, help="Output report id when using --run-ids.")
    parser.add_argument("--latest", action="store_true")
    parser.add_argument("--index", action="store_true", help="Generate results/reports/index.html for all scored runs.")
    parser.add_argument("--no-html", action="store_true", help="Only generate Markdown output.")
    return parser.parse_args()


def find_latest_run_id() -> str | None:
    scored_dir = PROJECT_ROOT / "results" / "scored"
    files = sorted(scored_dir.glob("*.jsonl"))
    if not files:
        return None
    return files[-1].stem


def generate_index() -> Path:
    scored_dir = PROJECT_ROOT / "results" / "scored"
    report_dir = PROJECT_ROOT / "results" / "reports"
    report_dir.mkdir(parents=True, exist_ok=True)
    entries = []
    for scored_path in sorted(scored_dir.glob("*.jsonl"), reverse=True):
        run_id = scored_path.stem
        try:
            rows = load_scored_rows(scored_path, run_id)
        except (OSError, json.JSONDecodeError):
            continue
        entries.append(index_entry(run_id, rows))
    output_path = report_dir / "index.html"
    output_path.write_text(build_index_html(entries), encoding="utf-8")
    return output_path


def index_entry(run_id: str, rows: list[dict[str, Any]]) -> dict[str, Any]:
    rows = enrich_rows(rows)
    models = sorted({str(row.get("model_display") or row.get("model")) for row in rows})
    tasks = sorted({str(row.get("task_id")) for row in rows})
    html_path = PROJECT_ROOT / "results" / "reports" / f"{run_id}.html"
    md_path = PROJECT_ROOT / "results" / "reports" / f"{run_id}.md"
    return {
        "run_id": run_id,
        "count": len(rows),
        "models": models,
        "tasks": tasks,
        "avg_score": mean(score_values(rows)) if rows else 0.0,
        "weighted_score": benchmark_score(rows),
        "success_rate": rate(row.get("success") for row in rows),
        "weighted_solve_rate": benchmark_solve_rate(rows),
        "total_cost_usd": sum(cost_values(rows, "usd")),
        "total_cost_rmb": sum(cost_values(rows, "rmb")),
        "has_html": html_path.exists(),
        "has_md": md_path.exists(),
    }


def build_index_html(entries: list[dict[str, Any]]) -> str:
    rows = []
    for entry in entries:
        run_id = html.escape(str(entry["run_id"]))
        html_link = f"<a href=\"{run_id}.html\">HTML</a>" if entry["has_html"] else ""
        md_link = f"<a href=\"{run_id}.md\">Markdown</a>" if entry["has_md"] else ""
        rows.append(
            "<tr>"
            f"<td>{run_id}</td>"
            f"<td>{html.escape(', '.join(entry['models']))}</td>"
            f"<td>{len(entry['tasks'])}</td>"
            f"<td>{entry['count']}</td>"
            f"<td>{entry['avg_score']:.1f}</td>"
            f"<td>{entry['weighted_score']:.1f}</td>"
            f"<td>{entry['success_rate']:.1%}</td>"
            f"<td>{entry['weighted_solve_rate']:.1%}</td>"
            f"<td>{format_dual_cost(entry['total_cost_rmb'], entry['total_cost_usd'])}</td>"
            f"<td>{html_link} {md_link}</td>"
            "</tr>"
        )
    table = (
        '<table><tr><th>Run</th><th>模型</th><th>任务数</th><th>结果数</th>'
        '<th>平均分</th><th>加权综合分</th><th>成功率</th><th>加权解出率</th><th>总成本</th><th>报告</th></tr>'
        + "".join(rows)
        + "</table>"
    )
    return f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>评测报告索引</title>
  <style>
    body {{
      margin: 0;
      background: #f6f7f9;
      color: #17202a;
      font-family: "Segoe UI", Arial, sans-serif;
      line-height: 1.5;
    }}
    main {{
      max-width: 1180px;
      margin: 0 auto;
      padding: 28px;
    }}
    h1 {{
      margin: 0 0 20px;
      font-size: 28px;
      letter-spacing: 0;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      background: #ffffff;
      border: 1px solid #d9dee7;
      border-radius: 8px;
      overflow: hidden;
      font-size: 13px;
    }}
    th, td {{
      border-bottom: 1px solid #d9dee7;
      padding: 9px 10px;
      text-align: left;
      vertical-align: top;
    }}
    th {{
      color: #5f6b7a;
      font-weight: 600;
    }}
    a {{ color: #2563eb; }}
  </style>
</head>
<body>
  <main>
    <h1>评测报告索引</h1>
    {table}
  </main>
</body>
</html>
"""


def enrich_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    metadata = load_task_metadata()
    model_metadata = load_model_metadata()
    enriched: list[dict[str, Any]] = []
    for row in rows:
        copy = dict(row)
        task_meta = metadata.get(str(copy.get("task_id")), {})
        source = task_meta.get("source", {})
        model_name = str(copy.get("model") or "unknown")
        model_meta = model_metadata.get(model_name, {})
        copy.setdefault("model_id", model_meta.get("model_id", ""))
        copy["model_display"] = model_display_name(copy)
        copy.setdefault("task_title", task_meta.get("title"))
        copy.setdefault("difficulty", task_meta.get("difficulty"))
        copy.setdefault("language", task_meta.get("language"))
        copy.setdefault("tags", task_meta.get("tags", []))
        copy.setdefault("task_origin", source.get("origin", "unknown"))
        copy.setdefault("task_source_type", source.get("type", "unknown"))
        copy.setdefault("task_source_license", source.get("license", "unknown"))
        copy.setdefault("task_reference_url", source.get("reference_url", ""))
        copy.setdefault("task_source_adaptation", source.get("adaptation", ""))
        copy.setdefault("scoring_items", task_meta.get("scoring", {}).get("items", default_scoring_items()))
        copy = enrich_benchmark_row(copy, task_meta)
        if "expected_vuln_types" not in copy:
            expected = task_meta.get("expected", {})
            vulns = expected.get("vulnerabilities", []) if isinstance(expected, dict) else []
            copy["expected_vuln_types"] = [vuln.get("type", "unknown") for vuln in vulns]
            if not copy["expected_vuln_types"] and isinstance(expected, dict):
                copy["expected_vuln_types"] = [
                    expected.get("attack_type")
                    or expected.get("vulnerability_type")
                    or expected.get("flag_type")
                    or expected.get("tool_goal", "unknown")
                ]
        enriched.append(copy)
    return enriched


def load_model_metadata() -> dict[str, dict[str, Any]]:
    try:
        config = load_yaml(PROJECT_ROOT / "config" / "models.yaml")
    except OSError:
        return {}
    models = config.get("models", [])
    if not isinstance(models, list):
        return {}
    return {str(model.get("name")): model for model in models if model.get("name")}


def model_display_name(row: dict[str, Any]) -> str:
    name = str(row.get("model") or "unknown")
    model_id = str(row.get("model_id") or "")
    if model_id and model_id != name:
        return f"{name} / {model_id}"
    return name


def load_task_metadata() -> dict[str, dict[str, Any]]:
    return load_task_metadata_map(PROJECT_ROOT)


def build_markdown_report(report_id: str, rows: list[dict[str, Any]], run_ids: list[str] | None = None) -> str:
    lines = [f"# 评测报告：{report_id}", ""]
    if not rows:
        lines.append("没有找到结果。")
        return "\n".join(lines)

    run_ids = run_ids or sorted({str(row.get("run_id")) for row in rows})
    lines.extend(
        [
            "## 概览",
            "",
            f"- 包含 run：{', '.join(run_ids)}",
            f"- 结果总数：{len(rows)}",
            f"- 平均分：{mean(score_values(rows)):.1f}",
            f"- 加权综合分：{benchmark_score(rows):.1f}",
            f"- 成功率：{rate(row['success'] for row in rows):.1%}",
            f"- 加权解出率：{benchmark_solve_rate(rows):.1%}",
            f"- 平均延迟：{mean(float(row.get('latency_ms', 0)) for row in rows):.0f} ms",
            f"- 平均 token 数：{mean(total_tokens(row) for row in rows):.0f}",
            f"- 平均成本：{format_dual_cost(mean(cost_values(rows, 'rmb')), mean(cost_values(rows, 'usd')))}",
            f"- 总成本：{format_dual_cost(sum(cost_values(rows, 'rmb')), sum(cost_values(rows, 'usd')))}",
            "",
            f"HTML 图表报告：`{report_id}.html`",
            "",
        ]
    )
    lines.extend(render_group_table("按模型汇总", rows, "model_display"))
    lines.extend(render_weighted_group_table("按模型加权榜单", rows, "model_display"))
    lines.extend(render_markdown_diagnosis_summary(rows))
    if len(run_ids) > 1:
        lines.extend(render_group_table("按 Run 汇总", rows, "run_id"))
    lines.extend(render_group_table("按漏洞类型汇总", expand_by_vuln_type(rows), "vulnerability_type"))
    lines.extend(render_stat_table("按能力桶加权汇总", capability_stats(rows)))
    lines.extend(render_stat_table("按难度加权汇总", difficulty_stats(rows)))
    lines.extend(render_source_table(rows))
    lines.extend(render_markdown_task_details(rows))
    return "\n".join(lines) + "\n"


def render_group_table(title: str, rows: list[dict[str, Any]], key: str) -> list[str]:
    grouped = group_by(rows, key)
    lines = [
        f"## {title}",
        "",
        "| 名称 | 数量 | 平均分 | 成功率 | 平均延迟 ms | 平均 token | 平均成本 | 总成本 |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for name, group in sorted(grouped.items()):
        lines.append(
            f"| {name} | {len(group)} | {mean(score_values(group)):.1f} | "
            f"{rate(row['success'] for row in group):.1%} | "
            f"{mean(float(row.get('latency_ms', 0)) for row in group):.0f} | "
            f"{mean(total_tokens(row) for row in group):.0f} | "
            f"{format_dual_cost(mean(cost_values(group, 'rmb')), mean(cost_values(group, 'usd')))} | "
            f"{format_dual_cost(sum(cost_values(group, 'rmb')), sum(cost_values(group, 'usd')))} |"
        )
    lines.append("")
    return lines


def render_weighted_group_table(title: str, rows: list[dict[str, Any]], key: str) -> list[str]:
    grouped = group_by(rows, key)
    lines = [
        f"## {title}",
        "",
        "| 名称 | 结果数 | 题目权重 | 加权综合分 | 加权解出率 | 原平均分 | 原成功率 |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    stats = []
    for name, group in grouped.items():
        stats.append((name, group, benchmark_score(group)))
    for name, group, weighted in sorted(stats, key=lambda item: (-item[2], str(item[0]))):
        lines.append(
            f"| {name} | {len(group)} | {total_effective_weight(group):.1f} | {weighted:.1f} | "
            f"{benchmark_solve_rate(group):.1%} | {mean(score_values(group)):.1f} | "
            f"{rate(row['success'] for row in group):.1%} |"
        )
    lines.append("")
    return lines


def render_stat_table(title: str, stats: list[dict[str, Any]]) -> list[str]:
    lines = [
        f"## {title}",
        "",
        "| 名称 | 结果数 | 题目权重 | 加权分 | 加权解出率 |",
        "|---|---:|---:|---:|---:|",
    ]
    for item in stats:
        lines.append(
            f"| {item['name']} | {item['count']} | {float(item.get('total_weight', 0)):.1f} | "
            f"{float(item.get('weighted_score', 0)):.1f} | {float(item.get('weighted_solve_rate', 0)):.1f}% |"
        )
    lines.append("")
    return lines


def render_source_table(rows: list[dict[str, Any]]) -> list[str]:
    seen: dict[str, dict[str, Any]] = {}
    for row in rows:
        seen[str(row.get("task_id"))] = row
    lines = [
        "## 题目来源",
        "",
        "| 任务 | 来源类型 | 来源 | 许可 | 参考链接 |",
        "|---|---|---|---|---|",
    ]
    for task_id, row in sorted(seen.items()):
        url = str(row.get("task_reference_url") or "")
        link = f"[链接]({url})" if url else ""
        lines.append(
            f"| {task_id} | {row.get('task_source_type') or ''} | {row.get('task_origin') or ''} | "
            f"{row.get('task_source_license') or ''} | {link} |"
        )
    lines.append("")
    return lines


def render_markdown_diagnosis_summary(rows: list[dict[str, Any]]) -> list[str]:
    lines = [
        "## 答案质量概览",
        "",
        "| 模型 | 结果数 | 合法 JSON | 平均 finding 数 | 平均问题数 | 常见问题 |",
        "|---|---:|---:|---:|---:|---|",
    ]
    for model, group in sorted(group_by(rows, "model_display").items()):
        valid_values = [
            (row.get("answer_diagnosis") or {}).get("valid_json")
            for row in group
            if "valid_json" in (row.get("answer_diagnosis") or {})
        ]
        valid_text = f"{rate(valid_values):.1%}" if valid_values else "无数据"
        finding_avg = mean(float((row.get("answer_diagnosis") or {}).get("finding_count", 0) or 0) for row in group)
        issue_avg = mean(float((row.get("answer_diagnosis") or {}).get("issue_count", 0) or 0) for row in group)
        issues = "；".join(common_issues(group)) or "无明显问题"
        lines.append(f"| {model} | {len(group)} | {valid_text} | {finding_avg:.1f} | {issue_avg:.1f} | {issues} |")
    lines.append("")
    return lines


def render_markdown_task_details(rows: list[dict[str, Any]]) -> list[str]:
    lines = ["## 模型任务明细", ""]
    for model, model_rows in sorted(group_by(rows, "model_display").items()):
        lines.extend([f"### {model}", ""])
        lines.extend(
            [
                "| 任务 | 平均分 | 分数组成 | 扣分说明 |",
                "|---|---:|---|---|",
            ]
        )
        for task_id, task_rows in sorted(group_by(model_rows, "task_id").items()):
            components = average_components(task_rows)
            component_text = "；".join(f"{label}: {components[key]:.1f}/{component_max(task_rows[0], key)}" for key, label, _, _ in COMPONENTS)
            reasons = aggregate_deductions(task_rows)
            reason_text = "；".join(reasons) if reasons else "无明显扣分项"
            lines.append(f"| {task_id} | {mean(score_values(task_rows)):.1f} | {component_text} | {reason_text} |")
        lines.append("")
    return lines


def build_html_report(report_id: str, rows: list[dict[str, Any]], run_ids: list[str] | None = None) -> str:
    if not rows:
        body = "<p>没有找到结果。</p>"
    else:
        run_ids = run_ids or sorted({str(row.get("run_id")) for row in rows})
        model_stats = summarize_group(rows, "model_display")
        sections = [
            render_kpis(rows, run_ids),
            section("答案质量概览", render_diagnosis_summary(rows)),
            section("按模型平均分", render_model_score_chart(model_stats)),
            section("按模型加权综合分", render_bar_chart(model_stats, "weighted_score", suffix="")),
            section("按模型分数组成", render_component_chart(rows)),
            section("按模型平均成本", render_cost_chart(model_stats)),
        ]
        if len(run_ids) > 1:
            sections.append(section("按 Run 平均分", render_bar_chart(summarize_group(rows, "run_id"), "avg_score", suffix="")))
        sections.extend(
            [
                section("按漏洞类型成功率", render_bar_chart(summarize_group(expand_by_vuln_type(rows), "vulnerability_type"), "success_rate", suffix="%")),
                section("按能力桶加权分", render_bar_chart(capability_stats(rows), "weighted_score", suffix="")),
                section("按难度加权分", render_bar_chart(difficulty_stats(rows), "weighted_score", suffix="")),
                section("题目来源", render_source_html_table(rows)),
                section("模型任务明细", render_model_details(rows)),
            ]
        )
        body = "\n".join(sections)
    return f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>评测报告 {html.escape(report_id)}</title>
  <style>
    :root {{
      color-scheme: light;
      --bg: #f6f7f9;
      --panel: #ffffff;
      --text: #17202a;
      --muted: #5f6b7a;
      --line: #d9dee7;
      --soft: #eef2f7;
      --bad: #b94646;
      --ok: #1f7a6d;
    }}
    body {{
      margin: 0;
      background: var(--bg);
      color: var(--text);
      font-family: "Segoe UI", Arial, sans-serif;
      line-height: 1.5;
    }}
    main {{
      max-width: 1220px;
      margin: 0 auto;
      padding: 28px;
    }}
    h1 {{
      margin: 0 0 20px;
      font-size: 28px;
      letter-spacing: 0;
    }}
    h2 {{
      margin: 0 0 14px;
      font-size: 18px;
      letter-spacing: 0;
    }}
    section, details.model-card {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 18px;
      margin: 16px 0;
      overflow-x: auto;
    }}
    details.model-card summary {{
      cursor: pointer;
      font-weight: 700;
      list-style: none;
    }}
    details.model-card summary::-webkit-details-marker {{ display: none; }}
    .model-summary {{
      display: grid;
      grid-template-columns: minmax(180px, 1fr) repeat(4, minmax(110px, auto));
      gap: 12px;
      align-items: center;
    }}
    .model-name {{
      display: flex;
      align-items: center;
      gap: 8px;
      font-size: 16px;
    }}
    .dot {{
      width: 12px;
      height: 12px;
      border-radius: 50%;
      display: inline-block;
    }}
    .metric span, .kpi span {{
      color: var(--muted);
      display: block;
      font-size: 12px;
      margin-bottom: 4px;
    }}
    .metric strong, .kpi strong {{ font-size: 20px; }}
    .kpis {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
      gap: 12px;
      margin-bottom: 18px;
    }}
    .kpi {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 14px;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 13px;
    }}
    th, td {{
      border-bottom: 1px solid var(--line);
      padding: 8px 10px;
      text-align: left;
      vertical-align: top;
    }}
    th {{
      color: var(--muted);
      font-weight: 600;
    }}
    .task-block {{
      border: 1px solid var(--line);
      border-radius: 8px;
      margin: 14px 0;
      padding: 12px;
      background: #fff;
    }}
    .task-head {{
      display: flex;
      justify-content: space-between;
      gap: 12px;
      flex-wrap: wrap;
      margin-bottom: 10px;
    }}
    .ok {{ color: var(--ok); font-weight: 600; }}
    .fail {{ color: var(--bad); font-weight: 600; }}
    .deductions {{
      margin: 8px 0 0;
      padding-left: 18px;
    }}
    .deductions li {{ margin: 2px 0; }}
    .none {{
      color: var(--ok);
      font-weight: 600;
    }}
    svg text {{
      fill: var(--text);
      font-size: 12px;
    }}
    .legend {{
      display: flex;
      flex-wrap: wrap;
      gap: 12px;
      margin: 8px 0 2px;
      color: var(--muted);
      font-size: 12px;
    }}
    .legend-item {{
      display: inline-flex;
      align-items: center;
      gap: 5px;
    }}
    .swatch {{
      width: 11px;
      height: 11px;
      border-radius: 2px;
      display: inline-block;
    }}
  </style>
</head>
<body>
  <main>
    <h1>评测报告：{html.escape(report_id)}</h1>
    {body}
  </main>
</body>
</html>
"""


def render_kpis(rows: list[dict[str, Any]], run_ids: list[str]) -> str:
    values = [
        ("Run 数", str(len(run_ids))),
        ("结果总数", str(len(rows))),
        ("平均分", f"{mean(score_values(rows)):.1f}"),
        ("加权综合分", f"{benchmark_score(rows):.1f}"),
        ("成功率", f"{rate(row['success'] for row in rows):.1%}"),
        ("加权解出率", f"{benchmark_solve_rate(rows):.1%}"),
        ("平均延迟", f"{mean(float(row.get('latency_ms', 0)) for row in rows):.0f} ms"),
        ("平均 token", f"{mean(total_tokens(row) for row in rows):.0f}"),
        ("平均成本", format_dual_cost(mean(cost_values(rows, "rmb")), mean(cost_values(rows, "usd")))),
        ("总成本", format_dual_cost(sum(cost_values(rows, "rmb")), sum(cost_values(rows, "usd")))),
    ]
    items = "\n".join(f"<div class=\"kpi\"><span>{label}</span><strong>{value}</strong></div>" for label, value in values)
    return f"<div class=\"kpis\">{items}</div>"


def render_diagnosis_summary(rows: list[dict[str, Any]]) -> str:
    grouped = group_by(rows, "model")
    header = "<tr><th>模型</th><th>结果数</th><th>合法 JSON</th><th>平均 finding 数</th><th>平均问题数</th><th>常见问题</th></tr>"
    body = []
    for model, group in sorted(grouped.items()):
        valid_values = [
            (row.get("answer_diagnosis") or {}).get("valid_json")
            for row in group
            if "valid_json" in (row.get("answer_diagnosis") or {})
        ]
        valid_text = f"{rate(valid_values):.1%}" if valid_values else "无数据"
        finding_avg = mean(float((row.get("answer_diagnosis") or {}).get("finding_count", 0) or 0) for row in group)
        issue_avg = mean(float((row.get("answer_diagnosis") or {}).get("issue_count", 0) or 0) for row in group)
        issues = common_issues(group)
        body.append(
            "<tr>"
            f"<td>{html.escape(model)}</td>"
            f"<td>{len(group)}</td>"
            f"<td>{valid_text}</td>"
            f"<td>{finding_avg:.1f}</td>"
            f"<td>{issue_avg:.1f}</td>"
            f"<td>{html.escape('；'.join(issues) if issues else '无明显问题')}</td>"
            "</tr>"
        )
    return f"<table>{header}{''.join(body)}</table>"


def render_model_score_chart(stats: list[dict[str, Any]]) -> str:
    colored = []
    color_map = model_color_map([str(item["name"]) for item in stats])
    for item in stats:
        copy = dict(item)
        copy["color"] = color_map[str(item["name"])]
        colored.append(copy)
    return render_bar_chart(colored, "avg_score", suffix="", use_item_color=True)


def render_cost_chart(stats: list[dict[str, Any]]) -> str:
    if any(float(item.get("avg_cost_rmb", 0)) > 0 for item in stats):
        metric = "avg_cost_rmb"
        value_format = "¥{:.6f}"
    elif any(float(item.get("avg_cost_usd", 0)) > 0 for item in stats):
        metric = "avg_cost_usd"
        value_format = "${:.6f}"
    else:
        return "<p>当前结果没有成本数据。请在 models.yaml 中配置 token 单价，并重新运行评测。</p>"
    colored = []
    color_map = model_color_map([str(item["name"]) for item in stats])
    for item in stats:
        copy = dict(item)
        copy["color"] = color_map[str(item["name"])]
        colored.append(copy)
    return render_bar_chart(colored, metric, suffix="", use_item_color=True, value_format=value_format)


def render_bar_chart(
    stats: list[dict[str, Any]],
    metric: str,
    suffix: str,
    use_item_color: bool = False,
    value_format: str | None = None,
) -> str:
    if not stats:
        return "<p>没有数据。</p>"
    width = 1000
    label_width = 220
    row_height = 34
    chart_width = width - label_width - 90
    height = 34 + row_height * len(stats)
    max_value = 100.0 if metric in {"avg_score", "success_rate", "weighted_score", "weighted_solve_rate"} else max(float(item[metric]) for item in stats) or 1.0
    rows = []
    for index, item in enumerate(stats):
        y = 24 + index * row_height
        value = float(item[metric])
        bar_width = 0 if max_value == 0 else (value / max_value) * chart_width
        color = str(item.get("color")) if use_item_color else ("#1f7a6d" if value >= 80 else "#345995" if value >= 50 else "#b94646")
        label = html.escape(str(item["name"]))
        display = value_format.format(value) if value_format else f"{value:.1f}{suffix}"
        rows.append(f"<text x=\"0\" y=\"{y + 16}\">{label}</text>")
        rows.append(f"<rect x=\"{label_width}\" y=\"{y}\" width=\"{bar_width:.1f}\" height=\"22\" rx=\"3\" fill=\"{color}\"></rect>")
        rows.append(f"<text x=\"{label_width + bar_width + 8:.1f}\" y=\"{y + 16}\">{display}</text>")
    return f"<svg viewBox=\"0 0 {width} {height}\" role=\"img\" width=\"100%\" height=\"{height}\">{''.join(rows)}</svg>"


def render_component_chart(rows: list[dict[str, Any]]) -> str:
    grouped = group_by(rows, "model")
    color_map = model_color_map(sorted(grouped))
    width = 1040
    label_width = 220
    chart_width = width - label_width - 110
    row_height = 52
    height = 36 + row_height * len(grouped)
    svg_parts = []
    legend = render_component_legend()
    for index, (model, model_rows) in enumerate(sorted(grouped.items())):
        y = 24 + index * row_height
        components = average_components(model_rows)
        x = label_width
        svg_parts.append(f"<text x=\"0\" y=\"{y + 18}\">{html.escape(model)}</text>")
        svg_parts.append(f"<circle cx=\"{label_width - 16}\" cy=\"{y + 12}\" r=\"5\" fill=\"{color_map[model]}\"></circle>")
        for key, _label, max_points, color in COMPONENTS:
            value = components[key]
            width_part = chart_width * (value / 100.0)
            if width_part > 0:
                svg_parts.append(
                    f"<rect x=\"{x:.1f}\" y=\"{y}\" width=\"{width_part:.1f}\" height=\"24\" "
                    f"rx=\"3\" fill=\"{color}\"><title>{html.escape(_label)} {value:.1f}/{max_points}</title></rect>"
                )
                text_color = "#ffffff" if width_part >= 34 else "#17202a"
                text_x = x + width_part / 2 if width_part >= 34 else x + width_part + 4
                anchor = "middle" if width_part >= 34 else "start"
                svg_parts.append(
                    f"<text x=\"{text_x:.1f}\" y=\"{y + 17}\" text-anchor=\"{anchor}\" "
                    f"style=\"fill:{text_color};font-size:11px\">{value:.1f}</text>"
                )
            x += width_part
        svg_parts.append(f"<text x=\"{label_width + chart_width + 10}\" y=\"{y + 18}\">{sum(components.values()):.1f}</text>")
    svg = f"<svg viewBox=\"0 0 {width} {height}\" role=\"img\" width=\"100%\" height=\"{height}\">{''.join(svg_parts)}</svg>"
    return legend + svg


def render_component_legend() -> str:
    items = []
    for _key, label, max_points, color in COMPONENTS:
        items.append(f"<span class=\"legend-item\"><span class=\"swatch\" style=\"background:{color}\"></span>{label} / {max_points}</span>")
    return f"<div class=\"legend\">{''.join(items)}</div>"


def render_model_details(rows: list[dict[str, Any]]) -> str:
    grouped = group_by(rows, "model_display")
    color_map = model_color_map(sorted(grouped))
    cards = []
    for model, model_rows in sorted(grouped.items()):
        cards.append(render_model_card(model, model_rows, color_map[model]))
    return "".join(cards)


def render_model_card(model: str, rows: list[dict[str, Any]], color: str) -> str:
    avg = mean(score_values(rows))
    success = rate(row["success"] for row in rows)
    latency = mean(float(row.get("latency_ms", 0)) for row in rows)
    tokens = mean(total_tokens(row) for row in rows)
    cost_text = format_dual_cost(sum(cost_values(rows, "rmb")), sum(cost_values(rows, "usd")))
    task_blocks = []
    for task_id, task_rows in sorted(group_by(rows, "task_id").items()):
        task_blocks.append(render_task_block(task_id, task_rows))
    summary = f"""
    <summary>
      <div class="model-summary">
        <div class="model-name"><span class="dot" style="background:{color}"></span>{html.escape(model)}</div>
        <div class="metric"><span>平均分</span><strong>{avg:.1f}</strong></div>
        <div class="metric"><span>成功率</span><strong>{success:.1%}</strong></div>
        <div class="metric"><span>任务数</span><strong>{len(group_by(rows, "task_id"))}</strong></div>
        <div class="metric"><span>平均延迟</span><strong>{latency:.0f} ms</strong></div>
      </div>
    </summary>
    """
    return (
        f"<details class=\"model-card\" open>{summary}<p>平均 token：{tokens:.0f} | "
        f"总成本：{cost_text}</p>{''.join(task_blocks)}</details>"
    )


def render_task_block(task_id: str, rows: list[dict[str, Any]]) -> str:
    avg = mean(score_values(rows))
    first = rows[0]
    title = first.get("task_title") or task_id
    vuln_type = ", ".join(str(item) for item in first.get("expected_vuln_types", []))
    components = average_components(rows)
    deductions = aggregate_deductions(rows)
    component_table = render_component_table(first, components)
    if deductions:
        deduction_html = "<ul class=\"deductions\">" + "".join(f"<li>{html.escape(item)}</li>" for item in deductions) + "</ul>"
    else:
        deduction_html = "<p class=\"none\">无明显扣分项。</p>"
    diagnosis = aggregate_diagnosis(rows)
    if diagnosis:
        diagnosis_html = "<ul class=\"deductions\">" + "".join(f"<li>{html.escape(item)}</li>" for item in diagnosis) + "</ul>"
    else:
        diagnosis_html = "<p class=\"none\">答案结构无明显问题。</p>"
    head = f"""
    <div class="task-head">
      <div><strong>{html.escape(task_id)}</strong> <span>{html.escape(str(title))}</span></div>
      <div>漏洞类型：{html.escape(vuln_type)} | 平均分：<strong>{avg:.1f}</strong> | 运行次数：{len(rows)}</div>
    </div>
    """
    return f"<div class=\"task-block\">{head}{component_table}<h4>扣分项</h4>{deduction_html}<h4>答案质量诊断</h4>{diagnosis_html}</div>"


def render_component_table(row: dict[str, Any], components: dict[str, float]) -> str:
    header = "<tr><th>评分项</th><th>得分</th><th>满分</th><th>状态</th></tr>"
    body = []
    for key, label, _default_max, _color in COMPONENTS:
        label = component_label(row, key, label)
        max_points = component_max(row, key)
        value = components[key]
        lost = max_points - value
        status = "满分" if lost <= 0.01 else f"扣 {lost:.1f}"
        body.append(
            f"<tr><td>{html.escape(label)}</td><td>{value:.1f}</td><td>{max_points}</td><td>{html.escape(status)}</td></tr>"
        )
    return f"<table>{header}{''.join(body)}</table>"


def render_source_html_table(rows: list[dict[str, Any]]) -> str:
    seen: dict[str, dict[str, Any]] = {}
    for row in rows:
        seen[str(row.get("task_id"))] = row
    header = "<tr><th>任务</th><th>来源类型</th><th>来源</th><th>许可</th><th>参考链接</th></tr>"
    body = []
    for task_id, row in sorted(seen.items()):
        url = str(row.get("task_reference_url") or "")
        link = f"<a href=\"{html.escape(url)}\">打开</a>" if url else ""
        body.append(
            "<tr>"
            f"<td>{html.escape(task_id)}</td>"
            f"<td>{html.escape(str(row.get('task_source_type') or ''))}</td>"
            f"<td>{html.escape(str(row.get('task_origin') or ''))}</td>"
            f"<td>{html.escape(str(row.get('task_source_license') or ''))}</td>"
            f"<td>{link}</td>"
            "</tr>"
        )
    return f"<table>{header}{''.join(body)}</table>"


def section(title: str, content: str) -> str:
    return f"<section><h2>{html.escape(title)}</h2>{content}</section>"


def summarize_group(rows: list[dict[str, Any]], key: str) -> list[dict[str, Any]]:
    grouped = group_by(rows, key)
    stats = []
    for name, group in grouped.items():
        stats.append(
            {
                "name": name,
                "count": len(group),
                "avg_score": mean(score_values(group)),
                "weighted_score": benchmark_score(group),
                "success_rate": rate(row["success"] for row in group) * 100,
                "weighted_solve_rate": benchmark_solve_rate(group) * 100,
                "avg_latency_ms": mean(float(row.get("latency_ms", 0)) for row in group),
                "avg_tokens": mean(total_tokens(row) for row in group),
                "avg_cost_usd": mean(cost_values(group, "usd")),
                "total_cost_usd": sum(cost_values(group, "usd")),
                "avg_cost_rmb": mean(cost_values(group, "rmb")),
                "total_cost_rmb": sum(cost_values(group, "rmb")),
            }
        )
    return sorted(stats, key=lambda item: (-float(item["avg_score"]), str(item["name"])))


def average_components(rows: list[dict[str, Any]]) -> dict[str, float]:
    values: dict[str, list[float]] = {key: [] for key, _label, _max_points, _color in COMPONENTS}
    for row in rows:
        row_components = component_scores(row)
        for key in values:
            values[key].append(row_components[key])
    return {key: mean(items) if items else 0.0 for key, items in values.items()}


def component_scores(row: dict[str, Any]) -> dict[str, float]:
    result = {key: 0.0 for key, _label, _max_points, _color in COMPONENTS}
    per_expected = row.get("grade_details", {}).get("per_expected", [])
    if not per_expected:
        return result
    for key in result:
        found = []
        for item in per_expected:
            try:
                found.append(float(item.get("items", {}).get(key, 0)))
            except (TypeError, ValueError):
                found.append(0.0)
        result[key] = mean(found) if found else 0.0
    return result


def aggregate_deductions(rows: list[dict[str, Any]]) -> list[str]:
    reasons: list[str] = []
    for row in rows:
        for reason in deduction_reasons(row):
            if reason not in reasons:
                reasons.append(reason)
    return reasons


def aggregate_diagnosis(rows: list[dict[str, Any]]) -> list[str]:
    issues: list[str] = []
    for row in rows:
        diagnosis = row.get("answer_diagnosis") or {}
        for issue in diagnosis.get("issues", []) or []:
            if issue not in issues:
                issues.append(str(issue))
        for file_name in diagnosis.get("hallucinated_files", []) or []:
            item = f"疑似臆造文件：{file_name}"
            if item not in issues:
                issues.append(item)
        for field in diagnosis.get("missing_fields", []) or []:
            item = f"缺少字段：{field}"
            if item not in issues:
                issues.append(item)
    return issues


def common_issues(rows: list[dict[str, Any]], limit: int = 3) -> list[str]:
    counts: dict[str, int] = defaultdict(int)
    for row in rows:
        for issue in aggregate_diagnosis([row]):
            counts[issue] += 1
    return [issue for issue, _count in sorted(counts.items(), key=lambda item: (-item[1], item[0]))[:limit]]


def deduction_reasons(row: dict[str, Any]) -> list[str]:
    reasons: list[str] = []
    if row.get("error"):
        reasons.append(f"调用错误：{row.get('error')}")
    parse_error = row.get("grade_details", {}).get("parse_error")
    if parse_error:
        reasons.append("JSON 解析失败或输出不符合要求，已扣格式分。")
    scores = component_scores(row)
    for key, label, _default_max, _color in COMPONENTS:
        label = component_label(row, key, label)
        max_points = component_max(row, key)
        lost = max_points - scores[key]
        if lost > 0.01:
            reasons.append(f"{label}扣 {lost:.1f} 分：{DEDUCTION_REASONS[key]}")
    if not reasons and float(row.get("score", 0)) < 100:
        reasons.append("总分未满，但评分器未返回更细的扣分来源。")
    return reasons


def component_label(row: dict[str, Any], key: str, default: str) -> str:
    labels = CATEGORY_COMPONENT_LABELS.get(str(row.get("category") or ""), {})
    return labels.get(key, default)


def component_max(row: dict[str, Any], key: str) -> float:
    scoring = row.get("scoring_items") or {}
    if key in scoring:
        try:
            return float(scoring[key])
        except (TypeError, ValueError):
            pass
    for component_key, _label, default_max, _color in COMPONENTS:
        if component_key == key:
            return float(default_max)
    return 0.0


def default_scoring_items() -> dict[str, int]:
    return {key: max_points for key, _label, max_points, _color in COMPONENTS}


def expand_by_vuln_type(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    expanded: list[dict[str, Any]] = []
    for row in rows:
        types = row.get("expected_vuln_types") or ["unknown"]
        for vuln_type in types:
            copy = dict(row)
            copy["vulnerability_type"] = str(vuln_type)
            expanded.append(copy)
    return expanded


def group_by(rows: list[dict[str, Any]], key: str) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[str(row.get(key, "unknown"))].append(row)
    return grouped


def model_color_map(models: list[str]) -> dict[str, str]:
    return {model: MODEL_COLORS[index % len(MODEL_COLORS)] for index, model in enumerate(sorted(models))}


def score_values(rows: list[dict[str, Any]]) -> list[float]:
    return [float(row.get("score", 0)) for row in rows]


def total_tokens(row: dict[str, Any]) -> float:
    usage = row.get("usage") or {}
    try:
        return float(usage.get("total_tokens", 0) or 0)
    except (TypeError, ValueError):
        return 0.0


def cost_values(rows: list[dict[str, Any]], currency: str = "usd") -> list[float]:
    values = []
    field = f"cost_{currency}"
    for row in rows:
        try:
            values.append(float(row.get(field, 0) or 0))
        except (TypeError, ValueError):
            values.append(0.0)
    return values


def format_dual_cost(rmb: float, usd: float) -> str:
    parts = []
    if rmb:
        parts.append(f"¥{rmb:.6f}")
    if usd:
        parts.append(f"${usd:.6f}")
    return " / ".join(parts) if parts else "0"


def rate(values: Any) -> float:
    items = list(values)
    if not items:
        return 0.0
    return sum(1 for value in items if value) / len(items)


if __name__ == "__main__":
    raise SystemExit(main())
