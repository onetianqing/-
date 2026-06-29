# 安全模型评测平台

这是面向 CTF、代码审计与网络安全任务的模型 API 评测平台。当前版本优先跑通单轮代码审计与日志分析闭环：

读取任务 -> 调用模型 -> 保存原始输出 -> 自动评分 -> 生成汇总报告。

## 安全边界

本平台仅用于授权、隔离、可控环境内的安全评测。任务、样例代码和后续靶场应限定在本地目录、Docker、VM 或沙箱中，不应对真实公网、真实内网资产或未授权系统执行扫描、攻击或利用。

## 当前功能

- 单轮代码审计评测
- 单轮日志/告警分析评测
- 单轮安全修复 Patch 评测
- 单轮 CTF 静态解题评测
- 单轮受控工具使用计划评测
- OpenAI-compatible API 适配器
- 本地 mock 模型，用于无 API key 的冒烟测试
- 审计类规则评分器 v2
- JSONL 结果记录
- Markdown 汇总报告
- 本地 HTML/SVG 图表报告
- 本地 Web 控制台，可通过 UI 选择模型、类别、题库来源、任务和测试次数
- 8 道内置审计样例：SQL 注入、XSS、SSRF、命令注入、路径穿越、公开项目/CVE 改写题
- 1 道 CVE 改写日志分析样例：Log4Shell / CVE-2021-44228 JNDI 探测
- 1 道公开项目改写 Patch 样例：OWASP Juice Shop 风格登录 SQL 注入修复
- 1 道公开 CTF 风格样例：picoCTF Base64 入门题
- 1 道 CVE 改写工具使用样例：Log4Shell 告警受控工具调查计划
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

启动本地 Web 控制台：

```bash
python ui/server.py --host 127.0.0.1 --port 8765
```

打开：

```text
http://127.0.0.1:8765/
```

Web 控制台支持选择模型、测试类别、题库来源、具体任务、测试次数、最大任务数、最大输出 token 和 run id；可以预览运行计划、启动评测、查看执行日志、进度、完成数量、百分比和耗时，并打开自动生成的 HTML/Markdown 报告。页面会显示模型名和具体型号，例如 `deepseek / deepseek-v4-pro`。API key 仍然通过启动服务前的环境变量提供，页面只显示 key 是否就绪，不显示 key 内容。

如果 8765 端口已被占用，可以换一个端口：

```bash
python ui/server.py --host 127.0.0.1 --port 8766
```

HTML 报告支持模型对比：

- 同一个 `run-id` 中的多个模型会合并在一份报告里。
- “按模型平均分”会用不同颜色展示不同模型。
- “按模型分数组成”会展示漏洞类型、定位、根因、复现方式、修复建议五个评分项的堆叠柱状图。
- “模型任务明细”会按模型合并，点击模型可以展开每道任务的结果。
- 每道任务会展示分数组成、扣分项和简短扣分原因。
- “按模型分数组成”堆叠图会在每个评分段上直接标注该段得分。

## 当前测试范围

当前可运行的评测类型包括：

- `audit`：单轮代码审计。
- `log_analysis`：单轮日志/告警分析。
- `patch`：单轮安全修复建议。
- `ctf`：静态 Jeopardy 风格 CTF 解题。
- `tool_use`：受控工具使用计划与多步骤安全任务。

CTF Docker 靶场、真实工具执行 agent、流量 PCAP 自动分析和 Patch 自动应用验证仍在设计文档后续路线中。

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
    response_format: json_object
    usd_per_1m_input_tokens: 0
    usd_per_1m_output_tokens: 0
```

GLM / 智谱示例：

```yaml
  - name: glm
    enabled: true
    provider: openai_compatible
    base_url: https://open.bigmodel.cn/api/paas/v4
    api_key_env: GLM_API_KEY
    model_id: glm-5.2
    max_tokens: 4096
    temperature: 0.2
    response_format: none
    usd_per_1m_input_tokens: 0
    usd_per_1m_output_tokens: 0
```

说明：平台会请求 `/chat/completions`，所以上面的 `base_url` 不需要包含 `/chat/completions`。`response_format: none` 表示不向该模型强制发送 JSON mode 参数，但 prompt 仍会要求模型只输出 JSON。

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

GLM 测试命令：

```powershell
$env:GLM_API_KEY="your_glm_api_key"
python runners/run_eval.py --models glm --category audit --source-type public-vulnerable-app-adapted,cve-minimal-reproduction --run-id glm-public-v05
python reports/generate_report.py --run-id glm-public-v05
```

DeepSeek 与 GLM 合并对比：

```powershell
$env:DEEPSEEK_API_KEY="your_deepseek_api_key"
$env:GLM_API_KEY="your_glm_api_key"
python runners/run_eval.py --models deepseek,glm --category audit --source-type public-vulnerable-app-adapted,cve-minimal-reproduction --run-id deepseek-vs-glm-v06
python reports/generate_report.py --run-id deepseek-vs-glm-v06
start E:\learn\model_test_exercise\results\reports\deepseek-vs-glm-v06.html
```

如果 DeepSeek 和 GLM 已经分开跑过，也可以把多个历史 run 合并成一份报告：

```powershell
python reports\generate_report.py --run-ids deepseek-public-v05,glm-public-v05 --output-id deepseek-vs-glm-merged
start E:\learn\model_test_exercise\results\reports\deepseek-vs-glm-merged.html
```

生成报告索引页：

```powershell
python reports\generate_report.py --index
start E:\learn\model_test_exercise\results\reports\index.html
```

## 模型原始输出语言

原始输出由模型直接生成，保存在 `results/raw/<run_id>/<model>/<task_id>.json`。早期版本的 schema 示例和标准答案多为英文，所以模型容易跟随英文输出。当前 prompt 已明确要求：JSON key 保持英文，字符串 value 使用中文；漏洞名、CVE、payload、文件名、函数名等专业名词可保留英文。

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

运行日志分析任务：

```bash
python runners/run_eval.py --models mock_auditor --category log_analysis --run-id log-smoke
python reports/generate_report.py --run-id log-smoke
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

正式调用 API 前执行评测前自检：

```bash
python runners/run_eval.py --models deepseek,glm --category audit --preflight --dry-run
python runners/run_eval.py --models deepseek,glm --category log_analysis --preflight --dry-run
python runners/run_eval.py --models deepseek,glm --category patch --preflight --dry-run
python runners/run_eval.py --models deepseek,glm --category ctf --preflight --dry-run
python runners/run_eval.py --models deepseek,glm --category tool_use --preflight --dry-run
```

说明：`--preflight` 会先检查任务元数据、模型配置和本次选中 API 模型的 key 环境变量。`--dry-run` 只构造 prompt 和跑评分链路，不调用模型；确认通过后再去掉 `--dry-run` 正式评测。

只查看运行计划，不写结果、不调用模型：

```bash
python runners/run_eval.py --models deepseek,glm --category audit --source-type public-vulnerable-app-adapted,cve-minimal-reproduction --plan-only
python runners/run_eval.py --models deepseek,glm --category log_analysis --plan-only
python runners/run_eval.py --models deepseek,glm --category patch --plan-only
python runners/run_eval.py --models deepseek,glm --category ctf --plan-only
python runners/run_eval.py --models deepseek,glm --category tool_use --plan-only
```

`--plan-only` 会输出模型数、任务数、重复次数、预计模型调用次数、粗略 input/output token 和按当前 `models.yaml` 价格估算的成本。token 和成本只是运行前估算，最终以 API 返回的 usage 和报告为准。

生成指定 run 的报告：

```bash
python reports/generate_report.py --run-id 20260625-153000
```

## 结果文件

- 原始模型输出：`results/raw/<run_id>/<model>/<task_id>.json`
- 评分 JSONL：`results/scored/<run_id>.jsonl`
- Markdown 汇总报告：`results/reports/<run_id>.md`
- HTML 图表报告：`results/reports/<run_id>.html`
- 报告索引页：`results/reports/index.html`

## 内置题目来源

当前任务集包含两类：

1. `synthetic`：平台自制回归样例，用于快速验证评分器和报告。
2. `public-vulnerable-app-adapted` / `cve-minimal-reproduction`：来自公开易受攻击项目或 CVE 公告的最小复现/参考改编题。

已加入的公开来源题：

- `audit-juice-sqli-001`：参考 OWASP Juice Shop 登录 SQL 注入场景，来源 https://github.com/juice-shop/juice-shop
- `audit-dvwa-cmdi-001`：参考 DVWA 命令注入训练模块，来源 https://github.com/digininja/DVWA
- `audit-cve-2021-41773-001`：参考 Apache HTTPD CVE-2021-41773 官方公告，来源 https://httpd.apache.org/security/vulnerabilities_24.html#CVE-2021-41773
- `log-log4shell-001`：参考 Log4Shell / CVE-2021-44228 公开漏洞描述改写日志分析题，来源 https://nvd.nist.gov/vuln/detail/CVE-2021-44228 和 https://logging.apache.org/log4j/2.x/security.html

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

1. 继续扩展 `audit` 与 `log_analysis` 公开来源题库，优先覆盖 CVE、公开 CTF 和真实业务代码改写样例。
2. 将运行计划预览继续接入 HTML 报告索引或单独保存为 JSON，方便留档和对比。
3. 第二阶段加入 Docker 靶场、工具执行器、CTF flag 评分和 Patch 修复验证。

## 成本估算

模型配置支持以下字段：

```yaml
usd_per_1m_input_tokens: 0
usd_per_1m_output_tokens: 0
rmb_per_1m_input_tokens: 0
rmb_per_1m_output_tokens: 0
```

含义是每 100 万 input/output token 的美元或人民币价格。价格经常变化，平台不会内置厂商价格；你需要按当前账户和模型价格手动填写。未填写或为 0 时，对应币种成本为 0。

成本会写入 `results/scored/<run_id>.jsonl` 每行的 `cost_usd` 和 `cost_rmb` 字段。HTML/Markdown 报告会展示平均成本、总成本、按模型平均成本图表，报告索引页也会展示总成本。

历史 run 离线重算成本：

```bash
python runners/recompute_costs.py --run-id deepseek-vs-glm-v06 --output-id deepseek-vs-glm-v06-costed
python reports/generate_report.py --run-id deepseek-vs-glm-v06-costed
```

这个命令不会覆盖原始 JSONL，会生成新的 `results/scored/<output-id>.jsonl`。

## 答案质量诊断

平台会对审计模型输出做轻量诊断，结果写入 `answer_diagnosis` 字段。诊断内容包括：

- 是否为合法 JSON
- findings 数量
- 是否缺少必填字段
- 是否引用题目文件列表之外的文件
- 是否引用标准答案之外的函数名

诊断不直接改变分数，只用于报告中辅助解释模型输出质量。历史 run 没有该字段时，报告会显示“无数据”。

## 最大输出 token 默认值

平台现在按测试类别设置默认 `max_tokens`，当前 `audit`、`log_analysis`、`patch`、`ctf`、`tool_use` 均默认为 `4096`。

命令行不传 `--max-tokens` 时使用类别默认值；传入 `--max-tokens 8192` 等参数时，以命令行覆盖值为准。Web 控制台中“最大输出 token”留空时使用类别默认值，填写数字时使用手动覆盖值。

每条评分结果会记录 `max_tokens` 和 `max_tokens_source`，便于排查输出截断或供应商返回空 content 的情况。

## v0.22 CTF 最小闭环

当前已新增 `ctf` 类别，用于评估模型从题面和附件中还原 flag 的能力。第一版只支持静态 Jeopardy 风格题，不启动 Docker，不允许工具执行。

示例命令：

```bash
python runners/validate.py --scope tasks --category ctf
python runners/run_eval.py --models mock_auditor --category ctf --run-id ctf-smoke
python reports/generate_report.py --run-id ctf-smoke
```

真实模型：

```bash
python runners/run_eval.py --models deepseek,glm --category ctf --preflight --dry-run
python runners/run_eval.py --models deepseek,glm --category ctf --run-id deepseek-glm-ctf-v022
python reports/generate_report.py --run-id deepseek-glm-ctf-v022
```

内置样例：

- `ctf-pico-base64-001`：picoCTF General Skills 风格 Base64 入门题，来源 https://picoctf.org/

## v0.25 Tool Use 最小闭环

当前已新增 `tool_use` 类别，用于评估模型在受控安全任务中选择工具、设置参数、安排步骤、形成证据链和遵守安全边界的能力。第一版只评估工具使用计划，不真实执行工具，不开放任意命令、端口扫描、漏洞利用或公网探测。

示例命令：

```bash
python runners/validate.py --scope tasks --category tool_use
python runners/run_eval.py --models mock_auditor --category tool_use --run-id tool-use-smoke
python reports/generate_report.py --run-id tool-use-smoke
```

真实模型：

```bash
python runners/run_eval.py --models deepseek,glm --category tool_use --preflight --dry-run
python runners/run_eval.py --models deepseek,glm --category tool_use --run-id deepseek-glm-tool-use-v025
python reports/generate_report.py --run-id deepseek-glm-tool-use-v025
```

内置样例：

- `tool-log4shell-triage-001`：Log4Shell / CVE-2021-44228 告警的受控工具调查计划，来源 https://nvd.nist.gov/vuln/detail/CVE-2021-44228
