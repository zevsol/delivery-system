# 新平台 Adapter 开发指南

## 先验证，再实现

当前仅维护 OpenAI/Codex Adapter；Claude、Cursor、GitHub Copilot、Gemini、Generic Agent、CLI 及其他 Adapter 不属于 V0 范围。维护者将某个平台纳入路线图后，才可查询其当前官方文档，并记录触发机制、资源读取、文件写入、审批、工具、安装和分发能力。未知能力必须保持 `TBD / Requires verification`。

## 实现顺序

1. 使用 `core/templates/adapter-contract.md` 创建 Draft Contract；
2. 映射三个 Core Role/Workflow，不改变角色边界；
3. 选择 Core 同步方式，并记录来源版本；
4. 为不可表达的审批、只读或外部写入语义设计安全降级；
5. 建立安装包与维护流程；
6. 在端到端测试阶段执行测试场景；
7. 通过 Conformance 后才将 Adapter 标为 Supported。

## 禁止事项

- 不复制 OpenAI/Codex 的文件格式后宣称支持另一平台；
- 不在 Adapter 中重写 Issue 粒度、变更管理或质量门；
- 不把未验证的工具权限当作已具备；
- 不以“平台限制”为由跳过用户批准，必须降级为草稿、预览或 Blocked 状态。
