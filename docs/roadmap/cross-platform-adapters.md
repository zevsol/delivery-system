# 跨平台 Adapter 路线

Core 的目标是跨平台一致的交付语义，而不是一次性支持所有宿主。

## 当前决定：搁置

项目当前只维护 OpenAI/Codex Adapter。GitHub Copilot 及其他平台的对接均已搁置，且不设恢复日期；本仓库不会为它们创建 Adapter 目录、平台配置、安装说明或发布流程。

此决定不影响 `core/` 的平台无关设计，也不代表任何平台已经或将会被支持。

## 恢复条件与顺序

只有在 OpenAI/Codex 完成真实场景验证，且项目所有者明确恢复跨平台工作后，才按以下顺序启动一个新平台：

1. 查询目标平台的当前官方格式、触发、权限、文件访问和分发机制；
2. 填写并评审 Adapter Contract；
3. 实现最小 Adapter，不能复制 OpenAI 的 Skill 文件后宣称兼容；
4. 使用相同 Core Conformance 场景验证；
5. 记录能力差异、安全降级和发布决定；
6. 再考虑下一个平台。

在恢复前，Claude、Cursor、GitHub Copilot、Gemini、Generic Agent 和 CLI 均为未实现且不在当前范围内的平台。
