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

## 报告语言

报告和图表的标题、表格、KPI、说明文字默认使用中文。漏洞类型、模型名、API、CVE 编号、token 等专业名词保留原文。

## 成功标准

当前默认 `score >= 80` 记为成功。
