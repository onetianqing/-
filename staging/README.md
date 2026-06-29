# Staging

互联网公开来源抓取结果先放在这里。

`runners/fetch_public_tasks.py` 会生成 source candidates；这些候选清单不是正式题库，必须先转成 task manifest、审计通过，再导入 `tasks/`。
