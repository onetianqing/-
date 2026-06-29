# 互联网公开题抓取与导入策略

后续可以从互联网抓取公开题目、公开 CTF、CVE 项目和真实业务代码样例，但必须先进入 staging 和审计流程，再导入正式题库。

## 原则

1. 保留来源：每道题必须有 `source.origin`、`source.reference_url`、`source.license`。
2. 尊重授权：不能复制不允许再分发的题面、附件或代码。
3. 优先改写：公开 CTF 题建议做本地非逐字改写，记录 adaptation。
4. 先审计后导入：抓取结果先转成 manifest，运行 `audit_manifest.py` 和 `import_tasks.py --dry-run`。
5. 批量分批：每批 500 到 2000 道，便于定位问题。

## 推荐流程

```bash
python runners/audit_manifest.py --manifest staging/public_ctf_batch_001.json
python runners/import_tasks.py --manifest staging/public_ctf_batch_001.json --dry-run
python runners/import_tasks.py --manifest staging/public_ctf_batch_001.json --validate
python runners/build_task_index.py --check
```

## 来源类型

建议使用以下 `source.type`：

- `public-ctf-adapted`
- `public-cve-adapted`
- `real-business-code-adapted`
- `open-source-project-adapted`
- `synthetic`

## 暂不自动抓取的内容

1. 需要登录或绕过访问限制的题库。
2. 明确禁止复制/再分发的题面和附件。
3. 带个人数据、真实密钥、真实业务敏感信息的样例。
4. 无法确认 license 或来源的批量数据。

## 后续工具方向

下一步可增加 `fetch_public_tasks.py`：

1. 从允许的公开 URL 抓取页面。
2. 抽取题目标题、分类、来源、参考链接。
3. 只把可授权内容或本地改写内容写入 staging manifest。
4. 自动运行 manifest 审计。
5. 审计通过后再由用户确认导入正式题库。

v0.32 已增加第一版：

```bash
python runners/fetch_public_tasks.py --offline --dry-run
python runners/fetch_public_tasks.py --source-id picoctf-reference --output staging/picoctf_candidates.json
```

该工具输出的是 source candidates，不是正式任务 manifest。候选清单还需要经过人工或后续转换器改写为 task manifest，再运行：

```bash
python runners/audit_manifest.py --manifest staging/public_ctf_batch_001.json
python runners/import_tasks.py --manifest staging/public_ctf_batch_001.json --dry-run
```

## Source Registry

示例来源登记文件：

```text
docs/examples/source_registry.json
```

后续抓取工具应先读取 source registry，只处理 `enabled=true` 且 `requires_login=false` 的来源。
