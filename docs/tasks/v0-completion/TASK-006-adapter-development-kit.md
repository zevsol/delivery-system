# TASK-006：跨平台 Adapter 开发套件

## 目标

在不假定 Claude、Cursor 或其他平台能力的前提下，为未来 Adapter 提供统一的契约模板、实现顺序和一致性要求。

## 交付物

- `core/templates/adapter-contract.md`
- `docs/maintainers/adapter-development.md`

## 完成标准

- 新平台必须先验证其官方能力；
- Adapter 不得创建第二套 Core 规则；
- 能力差异必须有降级策略和 Conformance 记录；
- 不创建未经核验的平台格式。

## 状态

completed
