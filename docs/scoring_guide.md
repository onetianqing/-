# 评分指南

审计评分器采用 100 分制，默认权重如下：

- 漏洞类型正确：20
- 定位准确：20
- 根因解释正确：20
- 攻击方式可复现：25
- 修复建议有效：15

## 自动评分说明

自动评分器会尝试解析模型输出 JSON，并根据标准答案中的类型、文件、函数、行号、根因关键词和修复关键词进行匹配。

如果模型输出不是合法 JSON，会扣 5 分。hard 任务建议进行人工复核，避免规则评分误判。

## v2 改动

- 支持多类漏洞别名：SQL Injection、XSS、SSRF、Command Injection、Path Traversal。
- 支持每道题在 `metadata.json` 中声明 `keywords`。
- 支持多个 expected vulnerability 的平均分聚合。
- 输出 `grade_details.per_expected`，便于查看每个漏洞点的细分得分。
- 报告生成器会按模型、漏洞类型、难度和任务聚合得分。
- HTML 报告内置 SVG 柱状图，可直接在浏览器中打开。

## 分数位置

- 机器可读评分：`results/scored/<run_id>.jsonl`
- 原始模型答案：`results/raw/<run_id>/<model>/<task_id>.json`
- Markdown 报告：`results/reports/<run_id>.md`
- HTML 图表报告：`results/reports/<run_id>.html`

## HTML 图表解释

HTML 报告会从 `grade_details.per_expected[].items` 读取细分项，展示以下分数组成：

- 漏洞类型：20 分
- 定位准确性：20 分
- 根因解释：20 分
- 复现方式：25 分
- 修复建议：15 分

如果某项未得满分，报告会在任务明细中给出简短扣分原因。原因是规则评分器根据标准答案、关键词和 JSON 结构推断出来的解释，适合作为快速定位问题的提示；hard 任务仍建议人工复核。

“按模型分数组成”堆叠图会在每个评分段上直接标注得分，鼠标悬停可看到该评分项的得分/满分。

## 报告语言

报告和图表的标题、表格、KPI、说明文字默认使用中文。漏洞类型、模型名、API、CVE 编号、token 等专业名词保留原文。

## 模型原始输出语言

原始输出由模型直接生成，不会被报告生成器翻译。当前审计 prompt 要求模型输出 JSON，其中 key 保持 schema 原样，字符串 value 使用中文；专业名词、代码标识符和 payload 可保留英文。

## 成功标准

当前默认 `score >= 80` 记为成功。

## 多 Run 合并

如果多个模型使用不同 `run-id` 分开跑，可以用报告生成器合并：

```bash
python reports/generate_report.py --run-ids run_a,run_b --output-id compare-a-b
```

合并报告会读取多个 `results/scored/<run_id>.jsonl`，并输出到 `results/reports/<output-id>.html` 和 `.md`。如果同一个模型、同一个任务在多个 run 中重复出现，报告会按模型和任务聚合平均值。

生成报告索引页：

```bash
python reports/generate_report.py --index
```

## 成本估算

模型调用成本由 `runners/model_client.py` 根据 usage 和 `config/models.yaml` 的价格字段估算：

```yaml
usd_per_1m_input_tokens: 0
usd_per_1m_output_tokens: 0
```

字段含义是每 100 万 input/output token 的美元价格。未配置或为 0 时，`cost_usd` 为 0。报告会展示平均成本、总成本、按模型平均成本和索引页总成本。

## 答案质量诊断

新运行的审计结果会包含 `answer_diagnosis` 字段。该字段不改变评分，只作为报告解释信号。

诊断项包括：

- `valid_json`：模型输出是否为合法 JSON。
- `finding_count`：findings 数量。
- `missing_fields`：缺失的必填字段。
- `hallucinated_files`：不在题目文件列表中的文件名。
- `unknown_functions`：不在标准答案函数列表中的函数名。
- `issues`：可读问题说明。

HTML/Markdown 报告会展示答案质量概览，并在模型任务明细中列出任务级诊断问题。
