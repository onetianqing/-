# 安全修复题编写指南

`patch` 任务用于评估模型是否能把给定脆弱代码转化为最小、可落地、低副作用的安全修复方案。当前第一版是单轮修复建议评测，不会自动把补丁写回源码并执行测试。

## 任务结构

```text
tasks/patch/<task_id>/
  metadata.json
  prompt.md
  files/
```

## expected 字段

```json
{
  "expected": {
    "vulnerability_type": "SQL Injection",
    "file": "files/login.js",
    "function": "login",
    "vulnerability_keywords": ["sql injection", "sqli", "sql"],
    "location_keywords": ["files/login.js", "login", "email", "password"],
    "root_cause_keywords": ["user input", "concatenate", "parameter"],
    "fix_keywords": ["parameterized", "placeholder", "bind", "?"],
    "test_keywords": ["unit test", "malicious", "normal login", "regression"]
  }
}
```

评分会映射到统一五个分项：类型判断、关键证据/定位、根因/时间线、复现/影响判断、修复/处置建议。

## 当前内置样例

- `patch-juice-sqli-001`：修复 OWASP Juice Shop 风格登录 SQL 注入。
- 来源：OWASP Juice Shop，https://github.com/juice-shop/juice-shop
- 授权：MIT。
- 改写方式：本地最小化、非逐字改写样例，只保留登录 SQL 注入训练模式用于评测。
