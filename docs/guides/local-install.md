# 本地安装、更新与卸载

> 当前版本为开发预览版。本地安装用于评估与贡献开发，尚未构成稳定版或官方目录发布。

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

也可根据每项 Skill 的描述由宿主隐式匹配。宿主对隐式匹配的实际行为会随版本和配置变化；请优先使用显式调用，并在使用前阅读 [使用指南](using-delivery-system.md)。

## 更新

拉取仓库更新后，重新安装或依照当前 Codex 的 plugin 更新机制刷新插件。若更新包含 Adapter 或 Core 改动，维护者还需要重新生成分发包并执行仓库校验；详见 [Adapter 与分发包维护](../maintainers/adapter-maintenance.md)。

## 卸载

```powershell
codex plugin remove delivery-system-openai --marketplace delivery-system
```
