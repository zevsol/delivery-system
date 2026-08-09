# V0 本地验收报告

> 状态：结构、静态与投影一致性验证通过；宿主安装与触发验证待执行。

## V0 范围

- 平台无关 Core Contract、三个工作流、五项治理政策、模板和 Schema；
- Core Behavior Conformance 场景与最小 fixture/expected 示例；
- 一个 skills-only OpenAI/Codex Adapter，含三个角色 Skill；
- 不包含 MCP、GitHub/Linear/Jira 写入、第二平台 Adapter、生成器或公开市场提交。

## 已完成验证

| 检查 | 结果 | 证据 |
|---|---|---|
| JSON Schema 可解析 | 通过 | `ConvertFrom-Json` |
| Plugin manifest 官方校验 | 通过 | `validate_plugin.py` |
| 三份 Skill 官方快速校验 | 通过 | `quick_validate.py`，UTF-8 模式 |
| V0 结构与投影一致性 | 通过 | `python scripts/validate_v0.py` |
| Core Behavior 场景 | 已定义 | `tests/conformance/core-behavior.md` |
| 宿主安装和触发 | 待执行 | 需要本地 marketplace 与新会话 |

## 已知限制

- Core 投影目前采用受控同步副本；`SYNC-MANIFEST.json` 与 `validate_v0.py` 检查其来源版本与关键条款，尚未实现自动生成器。
- OpenAI/Codex 的文件读写、审批和隐式触发需要在实际宿主环境验证。
- 未实现外部工具层或任何对外写操作。
- 未开始 Claude、Cursor、Generic Agent 或 CLI Adapter；它们均为 TBD / Requires verification。

## V0 通过条件

V0 在以下条件全部满足后可标记为本地可用：

1. `python scripts/validate_v0.py` 通过；
2. 官方 Plugin 和 Skill 校验器通过；
3. 插件经本地 marketplace 安装后，在新会话中可显式发现三项 Skill；当前 Adapter 目录与官方 marketplace 脚手架的 `plugins/<plugin-name>` 约定存在布局决策待定；
4. 使用 CB-001、CB-005、CB-006 的代表输入验证角色边界；
5. 安装或测试未改变用户项目文件，且所有限制均在报告中保留。
