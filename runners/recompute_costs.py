from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from runners.config_loader import load_yaml
from runners.model_client import estimate_cost


def main() -> int:
    args = parse_args()
    run_ids = selected_run_ids(args)
    models = load_model_configs()
    for run_id in run_ids:
        output_id = args.output_id if args.output_id and len(run_ids) == 1 else f"{run_id}-{args.suffix}"
        recompute_run(run_id, output_id, models)
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Recompute cost_usd/cost_rmb for existing scored JSONL files.")
    parser.add_argument("--run-id", default=None, help="Single run id to recompute.")
    parser.add_argument("--run-ids", default=None, help="Comma-separated run ids to recompute.")
    parser.add_argument("--all", action="store_true", help="Recompute all results/scored/*.jsonl files.")
    parser.add_argument("--output-id", default=None, help="Output id for a single --run-id.")
    parser.add_argument("--suffix", default="costed", help="Suffix for generated run ids when output-id is not set.")
    return parser.parse_args()


def selected_run_ids(args: argparse.Namespace) -> list[str]:
    if args.all:
        return [path.stem for path in sorted((PROJECT_ROOT / "results" / "scored").glob("*.jsonl"))]
    if args.run_ids:
        return [item.strip() for item in args.run_ids.split(",") if item.strip()]
    if args.run_id:
        return [args.run_id]
    raise SystemExit("Provide --run-id, --run-ids, or --all.")


def load_model_configs() -> dict[str, dict[str, Any]]:
    config = load_yaml(PROJECT_ROOT / "config" / "models.yaml")
    return {str(model.get("name")): model for model in config.get("models", []) if model.get("name")}


def recompute_run(run_id: str, output_id: str, models: dict[str, dict[str, Any]]) -> None:
    input_path = PROJECT_ROOT / "results" / "scored" / f"{run_id}.jsonl"
    if not input_path.exists():
        print(f"[WARN] scored file not found: {input_path}")
        return

    rows = []
    changed = 0
    missing_models: set[str] = set()
    for line in input_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        model_name = str(row.get("model") or "")
        model_config = models.get(model_name)
        if not model_config:
            missing_models.add(model_name)
            rows.append(row)
            continue
        usage = normalize_usage(row.get("usage") or {})
        old_usd = float(row.get("cost_usd", 0) or 0)
        old_rmb = float(row.get("cost_rmb", 0) or 0)
        new_usd = estimate_cost(model_config, usage, "usd")
        new_rmb = estimate_cost(model_config, usage, "rmb")
        row["cost_usd"] = new_usd
        row["cost_rmb"] = new_rmb
        row["cost_recomputed_from_run_id"] = run_id
        row["run_id"] = output_id
        if old_usd != new_usd or old_rmb != new_rmb:
            changed += 1
        rows.append(row)

    output_path = PROJECT_ROOT / "results" / "scored" / f"{output_id}.jsonl"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(json.dumps(row, ensure_ascii=False) for row in rows) + "\n", encoding="utf-8")
    print(f"[OK] {run_id} -> {output_id}: {len(rows)} rows, {changed} changed, output={output_path}")
    for model_name in sorted(missing_models):
        print(f"[WARN] model config not found, cost unchanged: {model_name}")


def normalize_usage(usage: dict[str, Any]) -> dict[str, int]:
    input_tokens = usage.get("input_tokens", usage.get("prompt_tokens", 0)) or 0
    output_tokens = usage.get("output_tokens", usage.get("completion_tokens", 0)) or 0
    total_tokens = usage.get("total_tokens", 0) or 0
    try:
        input_tokens_int = int(input_tokens)
        output_tokens_int = int(output_tokens)
        total_tokens_int = int(total_tokens) or input_tokens_int + output_tokens_int
    except (TypeError, ValueError):
        input_tokens_int = 0
        output_tokens_int = 0
        total_tokens_int = 0
    return {
        "input_tokens": input_tokens_int,
        "output_tokens": output_tokens_int,
        "total_tokens": total_tokens_int,
    }


if __name__ == "__main__":
    raise SystemExit(main())
