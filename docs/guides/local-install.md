# 本地安装与更新

## 前提

- 已安装 Codex CLI；
- 已克隆本仓库；
- 使用仓库根目录作为命令工作目录。

## 安装

```powershell
codex plugin marketplace add .
codex plugin add delivery-system-openai --marketplace delivery-system
```

确认安装：

```powershell
codex plugin list
```

预期条目为 `delivery-system-openai@delivery-system`，状态为 `installed, enabled`。

## 使用

在新会话中可显式调用：

```text
$idea-to-delivery
$audit-delivery
$execute-delivery
```

也可根据每项 Skill 的描述由宿主隐式匹配。首次使用应以 `tests/conformance/core-behavior.md` 的 CB-001、CB-005、CB-006 验证角色边界。

## 更新与卸载

仓库更新后，维护者先运行：

```powershell
python scripts/build_openai_distribution.py
python scripts/validate_v0.py
```

再依照当前 Codex 的 plugin 更新机制刷新或重新安装。卸载命令为：

```powershell
codex plugin remove delivery-system-openai --marketplace delivery-system
```
