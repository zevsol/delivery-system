# TASK-004：测试执行包与最终测试阶段

## 状态

pending — 仅在项目所有者明确启动最终测试后执行。

## 测试范围

1. 在目标 Codex/ChatGPT 环境的新会话中显式发现三项 Skill；
2. 运行 CB-001，确认模糊 Idea 进入 Discovery；
3. 运行 CB-005，确认新需求进入 Change Management；
4. 运行 CB-006，确认 Auditor 保持只读；
5. 使用至少一个小修复、一个从零 Idea、一个已有项目中型功能进行真实场景验证；
6. 记录实际输出、限制、失败项和修复 Issue。

## 通过标准

所有场景的角色边界、阻塞行为和追踪语义与 `core/` 一致；任何偏差必须先进入 Change Management 或修复 Issue，之后重新测试。
