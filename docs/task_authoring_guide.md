# 任务编写指南

当前任务以单轮代码审计为主，每个任务一个目录：

```text
tasks/audit/<task_id>/
  metadata.json
  prompt.md
  files/
```

## metadata.json 必填字段

- `id`：全局唯一任务 ID。
- `title`：题目标题。
- `category`：第一版使用 `audit`。
- `difficulty`：`easy`、`medium` 或 `hard`。
- `prompt_file`：任务说明文件。
- `files`：需要提供给模型的文件列表。
- `expected.vulnerabilities`：标准答案，用于自动评分。
- `scoring.items`：评分项权重。
- `source`：题目来源，用于区分自制、公开 CTF、CVE 片段或第三方授权数据。

## 编写建议

- 每题最好只有 1 个核心漏洞，便于第一版评分。
- 标准答案中写清漏洞类型、文件、函数、行号提示和根因。
- 可在标准答案中加入 `keywords`，帮助规则评分器更稳定地判断根因。
- prompt 不要泄露标准答案。
- 漏洞样例应限定在本地、授权、可控环境。
- 不要把来源不明的真实业务代码直接放入任务集。

## source 字段示例

公开项目改编题：

```json
{
  "source": {
    "type": "public-vulnerable-app-adapted",
    "origin": "OWASP Juice Shop",
    "license": "MIT",
    "reference_url": "https://github.com/juice-shop/juice-shop",
    "reference_note": "Public intentionally insecure web application used for trainings, demos and CTFs.",
    "adaptation": "Minimal non-verbatim local audit sample inspired by a public challenge pattern."
  }
}
```

CVE 最小复现题：

```json
{
  "source": {
    "type": "cve-minimal-reproduction",
    "origin": "Apache HTTP Server CVE-2021-41773 advisory",
    "license": "advisory-reference",
    "reference_url": "https://httpd.apache.org/security/vulnerabilities_24.html#CVE-2021-41773",
    "adaptation": "Minimal local reproduction of the vulnerability class; not upstream source code."
  }
}
```

平台自制题：

```json
{
  "source": {
    "type": "synthetic",
    "origin": "platform-authored",
    "license": "internal-evaluation",
    "note": "Hand-written local sample for evaluating audit behavior; not copied from a public CTF or CVE."
  }
}
```

## 当前内置样例

- `audit-sqli-001`：Flask 登录接口 SQL 注入
- `audit-xss-001`：Express 搜索接口反射型 XSS
- `audit-ssrf-001`：Flask URL 抓取接口 SSRF
- `audit-cmdi-001`：Flask Ping 诊断接口命令注入
- `audit-path-001`：Flask 文件下载接口路径穿越
- `audit-juice-sqli-001`：OWASP Juice Shop 风格登录 SQL 注入
- `audit-dvwa-cmdi-001`：DVWA 风格 Ping 功能命令注入
- `audit-cve-2021-41773-001`：Apache HTTPD CVE-2021-41773 风格路径穿越
