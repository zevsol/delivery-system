# V0 验证状态

本文档记录仓库验证边界，不等同于产品验收或稳定版发布。

## 已完成的仓库级验证

| 检查 | 状态 | 证据 |
|---|---|---|
| JSON Schema 可解析 | 通过 | PowerShell `ConvertFrom-Json` |
| Plugin manifest 校验 | 通过 | 官方 `validate_plugin.py` |
| 三份 Skill 快速校验 | 通过 | 官方 `quick_validate.py`，UTF-8 模式 |
| 结构、Core 投影与分发包一致性 | 通过 | `python scripts/validate_v0.py` |
| 本地 marketplace 安装 | 通过 | `delivery-system-openai@delivery-system`，版本 `0.1.0` |

## 尚未完成的宿主验证

- 在目标 ChatGPT/Codex 新会话中发现三项 Skill；
- 显式调用与隐式匹配行为；
- 文件读写、审批和工具权限在真实宿主中的边界；
- CB-001、CB-005、CB-006 的代表场景；
- 小修复、从零 Idea 和已有项目中型功能的端到端场景。

在这些验证完成前，OpenAI/Codex Adapter 的状态为本地可安装的实验性 Adapter，不能宣称为完整支持或生产可用。

## 已知限制

- Core 投影采用受控同步副本；仓库校验来源版本、关键条款和发行包哈希，但尚未自动生成投影文本；
- 不提供 MCP、外部工具层、GitHub/Linear/Jira 写入或内容发布；
- 其他平台 Adapter 不属于 V0 范围。
