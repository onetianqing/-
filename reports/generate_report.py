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


def main() -> int:
    args = parse_args()
    run_id = args.run_id
    if args.latest:
        run_id = find_latest_run_id()
    if not run_id:
        print("Provide --run-id or --latest.", file=sys.stderr)
        return 2

    scored_path = PROJECT_ROOT / "results" / "scored" / f"{run_id}.jsonl"
    if not scored_path.exists():
        print(f"Scored file not found: {scored_path}", file=sys.stderr)
        return 2

    rows = [json.loads(line) for line in scored_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    rows = enrich_rows(rows)
    output_dir = PROJECT_ROOT / "results" / "reports"
    output_dir.mkdir(parents=True, exist_ok=True)

    md_path = output_dir / f"{run_id}.md"
    md_path.write_text(build_markdown_report(run_id, rows), encoding="utf-8")
    print(f"Markdown report written: {md_path}")

    if not args.no_html:
        html_path = output_dir / f"{run_id}.html"
        html_path.write_text(build_html_report(run_id, rows), encoding="utf-8")
        print(f"HTML report written: {html_path}")
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate evaluation report.")
    parser.add_argument("--run-id", default=None)
    parser.add_argument("--latest", action="store_true")
    parser.add_argument("--no-html", action="store_true", help="Only generate Markdown output.")
    return parser.parse_args()


def find_latest_run_id() -> str | None:
    scored_dir = PROJECT_ROOT / "results" / "scored"
    files = sorted(scored_dir.glob("*.jsonl"))
    if not files:
        return None
    return files[-1].stem


def enrich_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    metadata = load_task_metadata()
    enriched: list[dict[str, Any]] = []
    for row in rows:
        copy = dict(row)
        task_meta = metadata.get(str(copy.get("task_id")), {})
        copy.setdefault("task_title", task_meta.get("title"))
        copy.setdefault("difficulty", task_meta.get("difficulty"))
        copy.setdefault("language", task_meta.get("language"))
        copy.setdefault("tags", task_meta.get("tags", []))
        copy.setdefault("task_origin", task_meta.get("source", {}).get("origin", "unknown"))
        copy.setdefault("task_source_type", task_meta.get("source", {}).get("type", "unknown"))
        copy.setdefault("task_source_license", task_meta.get("source", {}).get("license", "unknown"))
        copy.setdefault("task_reference_url", task_meta.get("source", {}).get("reference_url", ""))
        copy.setdefault("task_source_adaptation", task_meta.get("source", {}).get("adaptation", ""))
        if "expected_vuln_types" not in copy:
            vulns = task_meta.get("expected", {}).get("vulnerabilities", [])
            copy["expected_vuln_types"] = [vuln.get("type", "unknown") for vuln in vulns]
        enriched.append(copy)
    return enriched


def load_task_metadata() -> dict[str, dict[str, Any]]:
    metadata: dict[str, dict[str, Any]] = {}
    for path in (PROJECT_ROOT / "tasks").glob("*/*/metadata.json"):
        try:
            item = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        metadata[str(item.get("id"))] = item
    return metadata


def build_markdown_report(run_id: str, rows: list[dict[str, Any]]) -> str:
    lines = [f"# 评测报告：{run_id}", ""]
    if not rows:
        lines.append("没有找到结果。")
        return "\n".join(lines)

    lines.extend(
        [
            "## 概览",
            "",
            f"- 结果总数：{len(rows)}",
            f"- 平均分：{mean(score_values(rows)):.1f}",
            f"- 成功率：{_rate(row['success'] for row in rows):.1%}",
            f"- 平均延迟：{mean(float(row.get('latency_ms', 0)) for row in rows):.0f} ms",
            f"- 平均 token 数：{mean(total_tokens(row) for row in rows):.0f}",
            "",
            f"HTML 图表报告：`{run_id}.html`",
            "",
        ]
    )
    lines.extend(render_group_table("按模型汇总", rows, "model"))
    lines.extend(render_group_table("按漏洞类型汇总", expand_by_vuln_type(rows), "vulnerability_type"))
    lines.extend(render_group_table("按难度汇总", rows, "difficulty"))
    lines.extend(render_source_table(rows))
    lines.extend(render_repetition_table(rows))
    lines.extend(render_result_table(rows))
    return "\n".join(lines) + "\n"


def render_group_table(title: str, rows: list[dict[str, Any]], key: str) -> list[str]:
    grouped = group_by(rows, key)
    lines = [
        f"## {title}",
        "",
        "| 名称 | 数量 | 平均分 | 成功率 | 平均延迟 ms | 平均 token |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for name, group in sorted(grouped.items()):
        lines.append(
            f"| {name} | {len(group)} | {mean(score_values(group)):.1f} | "
            f"{_rate(row['success'] for row in group):.1%} | "
            f"{mean(float(row.get('latency_ms', 0)) for row in group):.0f} | "
            f"{mean(total_tokens(row) for row in group):.0f} |"
        )
    lines.append("")
    return lines


def render_repetition_table(rows: list[dict[str, Any]]) -> list[str]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        key = f"{row.get('model')} / {row.get('task_id')}"
        grouped[key].append(row)
    repeated = {key: value for key, value in grouped.items() if len(value) > 1}
    if not repeated:
        return []
    lines = [
        "## 重复运行稳定性",
        "",
        "| 模型 / 任务 | 运行次数 | 平均分 | 最低分 | 最高分 | 标准差 |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for key, group in sorted(repeated.items()):
        scores = score_values(group)
        lines.append(
            f"| {key} | {len(group)} | {mean(scores):.1f} | {min(scores):.0f} | "
            f"{max(scores):.0f} | {stdev(scores):.1f} |"
        )
    lines.append("")
    return lines


def render_result_table(rows: list[dict[str, Any]]) -> list[str]:
    lines = [
        "## 明细结果",
        "",
        "| 模型 | 任务 | 漏洞类型 | 分数 | 成功 | 重复序号 | 来源 | 错误 |",
        "|---|---|---|---:|---|---:|---|---|",
    ]
    for row in rows:
        error = str(row.get("error") or "")
        vuln_type = ", ".join(str(item) for item in row.get("expected_vuln_types", []))
        lines.append(
            f"| {row.get('model')} | {row.get('task_id')} | {vuln_type} | {row.get('score')} | "
            f"{yes_no(row.get('success'))} | {row.get('repetition', 1)} | {row.get('task_origin') or ''} | "
            f"{error.replace('|', '/')[:120]} |"
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


def build_html_report(run_id: str, rows: list[dict[str, Any]]) -> str:
    if not rows:
        body = "<p>没有找到结果。</p>"
    else:
        model_stats = summarize_group(rows, "model")
        type_stats = summarize_group(expand_by_vuln_type(rows), "vulnerability_type")
        difficulty_stats = summarize_group(rows, "difficulty")
        task_stats = summarize_group(rows, "task_id")
        body = "\n".join(
            [
                render_kpis(rows),
                section("按模型平均分", render_bar_chart(model_stats, "avg_score", suffix="")),
                section("按漏洞类型成功率", render_bar_chart(type_stats, "success_rate", suffix="%")),
                section("按难度平均分", render_bar_chart(difficulty_stats, "avg_score", suffix="")),
                section("按任务平均分", render_bar_chart(task_stats, "avg_score", suffix="")),
                section("题目来源", render_source_html_table(rows)),
                section("明细结果", render_html_table(rows)),
            ]
        )
    return f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>评测报告 {html.escape(run_id)}</title>
  <style>
    :root {{
      color-scheme: light;
      --bg: #f6f7f9;
      --panel: #ffffff;
      --text: #17202a;
      --muted: #5f6b7a;
      --line: #d9dee7;
      --accent: #1f7a6d;
      --accent-2: #345995;
      --bad: #b94646;
    }}
    body {{
      margin: 0;
      background: var(--bg);
      color: var(--text);
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
    h2 {{
      margin: 0 0 14px;
      font-size: 18px;
      letter-spacing: 0;
    }}
    section {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 18px;
      margin: 16px 0;
      overflow-x: auto;
    }}
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
    .kpi span {{
      color: var(--muted);
      display: block;
      font-size: 12px;
      margin-bottom: 5px;
    }}
    .kpi strong {{
      font-size: 24px;
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
    .ok {{ color: var(--accent); font-weight: 600; }}
    .fail {{ color: var(--bad); font-weight: 600; }}
    svg text {{
      fill: var(--text);
      font-size: 12px;
    }}
    .axis {{
      stroke: var(--line);
      stroke-width: 1;
    }}
  </style>
</head>
<body>
  <main>
    <h1>评测报告：{html.escape(run_id)}</h1>
    {body}
  </main>
</body>
</html>
"""


def render_kpis(rows: list[dict[str, Any]]) -> str:
    values = [
        ("结果总数", str(len(rows))),
        ("平均分", f"{mean(score_values(rows)):.1f}"),
        ("成功率", f"{_rate(row['success'] for row in rows):.1%}"),
        ("平均延迟", f"{mean(float(row.get('latency_ms', 0)) for row in rows):.0f} ms"),
        ("平均 token", f"{mean(total_tokens(row) for row in rows):.0f}"),
    ]
    items = "\n".join(f"<div class=\"kpi\"><span>{label}</span><strong>{value}</strong></div>" for label, value in values)
    return f"<div class=\"kpis\">{items}</div>"


def render_bar_chart(stats: list[dict[str, Any]], metric: str, suffix: str) -> str:
    if not stats:
        return "<p>No data.</p>"
    width = 980
    label_width = 210
    row_height = 34
    chart_width = width - label_width - 90
    height = 34 + row_height * len(stats)
    max_value = 100.0 if metric in {"avg_score", "success_rate"} else max(float(item[metric]) for item in stats) or 1.0
    rows = []
    for index, item in enumerate(stats):
        y = 24 + index * row_height
        value = float(item[metric])
        bar_width = 0 if max_value == 0 else (value / max_value) * chart_width
        color = "#1f7a6d" if value >= 80 else "#345995" if value >= 50 else "#b94646"
        label = html.escape(str(item["name"]))
        display = f"{value:.1f}{suffix}"
        rows.append(f"<text x=\"0\" y=\"{y + 16}\">{label}</text>")
        rows.append(f"<rect x=\"{label_width}\" y=\"{y}\" width=\"{bar_width:.1f}\" height=\"22\" rx=\"3\" fill=\"{color}\"></rect>")
        rows.append(f"<text x=\"{label_width + bar_width + 8:.1f}\" y=\"{y + 16}\">{display}</text>")
    return f"<svg viewBox=\"0 0 {width} {height}\" role=\"img\" width=\"100%\" height=\"{height}\">{''.join(rows)}</svg>"


def render_html_table(rows: list[dict[str, Any]]) -> str:
    header = "<tr><th>模型</th><th>任务</th><th>漏洞类型</th><th>分数</th><th>成功</th><th>延迟</th><th>Tokens</th></tr>"
    body = []
    for row in rows:
        success = bool(row.get("success"))
        success_html = f"<span class=\"{'ok' if success else 'fail'}\">{yes_no(success)}</span>"
        vuln_type = ", ".join(str(item) for item in row.get("expected_vuln_types", []))
        body.append(
            "<tr>"
            f"<td>{html.escape(str(row.get('model')))}</td>"
            f"<td>{html.escape(str(row.get('task_id')))}</td>"
            f"<td>{html.escape(vuln_type)}</td>"
            f"<td>{html.escape(str(row.get('score')))}</td>"
            f"<td>{success_html}</td>"
            f"<td>{html.escape(str(row.get('latency_ms', 0)))} ms</td>"
            f"<td>{total_tokens(row):.0f}</td>"
            "</tr>"
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
                "success_rate": _rate(row["success"] for row in group) * 100,
                "avg_latency_ms": mean(float(row.get("latency_ms", 0)) for row in group),
                "avg_tokens": mean(total_tokens(row) for row in group),
            }
        )
    return sorted(stats, key=lambda item: (-float(item["avg_score"]), str(item["name"])))


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


def score_values(rows: list[dict[str, Any]]) -> list[float]:
    return [float(row.get("score", 0)) for row in rows]


def total_tokens(row: dict[str, Any]) -> float:
    usage = row.get("usage") or {}
    try:
        return float(usage.get("total_tokens", 0) or 0)
    except (TypeError, ValueError):
        return 0.0


def yes_no(value: Any) -> str:
    return "是" if bool(value) else "否"


def _rate(values: Any) -> float:
    items = list(values)
    if not items:
        return 0.0
    return sum(1 for value in items if value) / len(items)


if __name__ == "__main__":
    raise SystemExit(main())
