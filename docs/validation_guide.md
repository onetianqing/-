# 平台自检指南

`runners/validate.py` 用于在正式评测前检查平台配置和任务元数据。

## 常用命令

```bash
python runners/validate.py --scope all
python runners/validate.py --scope tasks --category audit
python runners/validate.py --scope tasks --category log_analysis
python runners/validate.py --scope tasks --category patch
python runners/validate.py --scope tasks --category ctf
python runners/validate.py --scope models
python runners/validate.py --scope all --json
```

也可以在正式评测前让 `run_eval.py` 自动执行自检：

```bash
python runners/run_eval.py --models deepseek,glm --category audit --preflight --dry-run
python runners/run_eval.py --models deepseek,glm --category log_analysis --preflight --dry-run
python runners/run_eval.py --models deepseek,glm --category patch --preflight --dry-run
python runners/run_eval.py --models deepseek,glm --category ctf --preflight --dry-run
```

`--preflight` 会检查任务元数据、模型配置和本次选中 API 模型的 key 环境变量。`--preflight-strict` 会把 warning 也视为阻断项，适合发布正式基准前使用。

如果只想查看预计运行规模和成本，不想写结果文件，可以使用：

```bash
python runners/run_eval.py --models deepseek,glm --category audit --plan-only
python runners/run_eval.py --models deepseek,glm --category log_analysis --plan-only
python runners/run_eval.py --models deepseek,glm --category patch --plan-only
python runners/run_eval.py --models deepseek,glm --category ctf --plan-only
```

`--plan-only` 会打印模型数、任务数、重复次数、预计调用次数、粗略 token 数和按 `models.yaml` 当前价格估算的成本，然后直接退出。

## 检查内容

任务通用检查：

- `metadata.json` 必填字段是否完整。
- 任务 ID 是否重复。
- `prompt_file` 是否存在。
- `files` 中的题目文件是否存在。
- `source` 字段是否包含 `type`、`origin`、`license`。
- 公开来源、业务代码或 CVE 任务是否包含 `reference_url`。
- `scoring.items` 是否包含五个评分项，且总和是否与 `total` 一致。

代码审计题检查：

- `expected.vulnerabilities` 是否为非空数组。
- 每个漏洞标准答案是否包含 `type`、`file`、`function`、`root_cause`。
- 标准答案里的文件是否出现在 `files` 列表中。

日志分析题检查：

- `expected.attack_type` 是否存在。
- `attack_type_keywords`、`evidence_keywords`、`timeline_keywords`、`impact_keywords`、`remediation_keywords` 是否为非空数组。

模型检查：

- 模型名称是否重复。
- `openai_compatible` 模型是否包含 `base_url` 和 `api_key_env`。
- 已启用 API 模型对应环境变量是否已设置。
- token 单价字段是否为数字。

自检只检查环境变量是否存在，不读取、不打印 API key 值。
