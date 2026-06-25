# 安全模型评测平台

这是面向 CTF、代码审计与网络安全任务的模型 API 评测平台。当前版本优先跑通单轮代码审计闭环：

读取任务 -> 调用模型 -> 保存原始输出 -> 自动评分 -> 生成汇总报告。

## 安全边界

本平台仅用于授权、隔离、可控环境内的安全评测。任务、样例代码和后续靶场应限定在本地目录、Docker、VM 或沙箱中，不应对真实公网、真实内网资产或未授权系统执行扫描、攻击或利用。

## 当前功能

- 单轮代码审计评测
- OpenAI-compatible API 适配器
- 本地 mock 模型，用于无 API key 的冒烟测试
- 审计类规则评分器 v2
- JSONL 结果记录
- Markdown 汇总报告
- 本地 HTML/SVG 图表报告
- 5 道内置审计样例：SQL 注入、XSS、SSRF、命令注入、路径穿越
- 模型与任务列表查看
- 单次运行内重复评测
- 题目来源元数据记录
- 可按题目来源类型过滤运行

## 目录结构

```text
model_test_exercise/
  config/
  graders/
  prompts/
  reports/
  results/
  runners/
  tasks/
  docs/
```

## 快速开始

在项目根目录运行离线冒烟测试：

```bash
python runners/run_eval.py --models mock_auditor --category audit
```

生成报告：

```bash
python reports/generate_report.py --latest
```

报告会同时生成 Markdown 和 HTML。HTML 是本地静态文件，内置 SVG 图表，不依赖网络或 CDN。

## 接入真实模型 API

编辑 `config/models.yaml`，把 OpenAI-compatible 模型的 `enabled` 改为 `true`，并设置对应环境变量。

DeepSeek 示例：

```yaml
  - name: deepseek
    enabled: true
    provider: openai_compatible
    base_url: https://api.deepseek.com
    api_key_env: DEEPSEEK_API_KEY
    model_id: deepseek-v4-flash
    max_tokens: 4096
    temperature: 0.2
```

通用 OpenAI-compatible 示例：

```bash
set MODEL_A_API_KEY=your_api_key
python runners/run_eval.py --models model_a --category audit
```

如果使用 PowerShell：

```powershell
$env:MODEL_A_API_KEY="your_api_key"
python runners/run_eval.py --models model_a --category audit
```

## 常用命令

查看模型：

```bash
python runners/run_eval.py --list-models
```

查看任务：

```bash
python runners/run_eval.py --list-tasks
```

只查看公开来源/CVE 改编题：

```bash
python runners/run_eval.py --list-tasks --source-type public-vulnerable-app-adapted,cve-minimal-reproduction
```

运行所有已启用模型和审计任务：

```bash
python runners/run_eval.py --models all --category audit
```

指定温度：

```bash
python runners/run_eval.py --models model_a --category audit --temperature 0.2
```

每个模型-任务组合重复运行 3 次：

```bash
python runners/run_eval.py --models model_a --category audit --repetitions 3 --run-id model-a-audit-r3
```

只运行公开来源/CVE 改编题：

```bash
python runners/run_eval.py --models deepseek --category audit --source-type public-vulnerable-app-adapted,cve-minimal-reproduction --run-id deepseek-public-sources
```

只构造 prompt，不调用模型：

```bash
python runners/run_eval.py --models mock_auditor --category audit --dry-run
```

生成指定 run 的报告：

```bash
python reports/generate_report.py --run-id 20260625-153000
```

## 结果文件

- 原始模型输出：`results/raw/<run_id>/<model>/<task_id>.json`
- 评分 JSONL：`results/scored/<run_id>.jsonl`
- Markdown 汇总报告：`results/reports/<run_id>.md`
- HTML 图表报告：`results/reports/<run_id>.html`

## 内置题目来源

当前任务集包含两类：

1. `synthetic`：平台自制回归样例，用于快速验证评分器和报告。
2. `public-vulnerable-app-adapted` / `cve-minimal-reproduction`：来自公开易受攻击项目或 CVE 公告的最小复现/参考改编题。

已加入的公开来源题：

- `audit-juice-sqli-001`：参考 OWASP Juice Shop 登录 SQL 注入场景，来源 https://github.com/juice-shop/juice-shop
- `audit-dvwa-cmdi-001`：参考 DVWA 命令注入训练模块，来源 https://github.com/digininja/DVWA
- `audit-cve-2021-41773-001`：参考 Apache HTTPD CVE-2021-41773 官方公告，来源 https://httpd.apache.org/security/vulnerabilities_24.html#CVE-2021-41773

这些题均为最小复现或非逐字改编，目的是让评测题具备可追踪来源，同时避免把大段第三方源码直接复制进平台。

每道题的 `metadata.json` 都包含 `source` 字段：

```json
{
  "type": "public-vulnerable-app-adapted",
  "origin": "OWASP Juice Shop",
  "license": "MIT",
  "reference_url": "https://github.com/juice-shop/juice-shop"
}
```

## 当前评价方式

评分器会读取 `metadata.json` 里的标准答案，并根据模型输出的 JSON 做规则评分。分数写入 `results/scored/<run_id>.jsonl`，细分项写入每行的 `grade_details` 字段。当前默认 `score >= 80` 判定为成功。

报告和图表除漏洞名、模型名、CVE、API、token 等专业名词外，默认使用中文输出。

## 下一步建议

1. 继续扩展到 10-20 道审计任务，加入多文件项目和多漏洞混合题。
2. 为 hard 任务加入人工复核字段。
3. 第二阶段加入 Docker 靶场、工具执行器和 CTF flag 评分。
