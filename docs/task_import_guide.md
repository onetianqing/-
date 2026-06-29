# 题库批量导入指南

v0.30 开始，平台支持用 manifest 批量导入任务。

## 基本流程

```bash
python runners/audit_manifest.py --manifest docs/examples/ctf_import_manifest.json
python runners/import_tasks.py --manifest docs/examples/ctf_import_manifest.json --dry-run
python runners/import_tasks.py --manifest docs/examples/ctf_import_manifest.json --validate
```

审计器会在导入前检查：

1. 来源字段是否完整。
2. `reference_url`、`license`、`benchmark` 是否缺失。
3. 类别、来源类型、能力桶、难度、license 分布。
4. CTF 确定性编码题附件是否能解码出标准答案。

导入器会完成：

1. 检查 manifest 结构和任务 ID。
2. 写入 `tasks/<category>/<task_id>/metadata.json`。
3. 写入 `prompt.md` 和附件文件。
4. 重建 `tasks/task_index.json`。
5. 可选运行受影响类别的题库校验。

## 覆盖已有任务

默认不会覆盖已有任务目录。确实需要覆盖时使用：

```bash
python runners/import_tasks.py --manifest docs/examples/ctf_import_manifest.json --overwrite --validate
```

## manifest 结构

manifest 顶层字段：

```json
{
  "schema_version": 1,
  "defaults": {},
  "tasks": []
}
```

`defaults` 中可以放公共的 `source`、`benchmark`、`scoring`、`execution`、`prompt`、`metadata` 等字段。每个任务可以覆盖默认值。

## 大规模导入建议

1. 每批先控制在 500 到 2000 道，便于定位坏题。
2. 每批导入前先运行 `audit_manifest.py`。
3. 每批导入前再运行 `--dry-run`。
4. 导入后必须运行 `--validate`。
5. CTF 确定性编码题建议加 `tags` 或 `consistency_checks`，例如 `base64`、`hex`、`rot13`、`morse`。
6. 来源必须写清楚 `source.type`、`source.origin`、`source.license`、`source.reference_url`。

## 当前边界

导入器只负责本地文件题库落盘和校验，不会自动抓取互联网题目，也不会绕过公开题库的 license。公开 CTF、CVE、真实业务代码样例应先整理成合法可用的 manifest，再导入平台。

互联网抓取请先使用：

```bash
python runners/fetch_public_tasks.py --offline --dry-run
```

抓取结果是 `staging` 候选清单，不是正式 manifest。
