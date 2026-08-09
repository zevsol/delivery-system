# OpenAI/Codex Adapter 与分发包维护

`core/` 是交付语义的唯一来源；`adapters/delivery-system-openai/` 是 OpenAI/Codex Adapter 的 canonical 源；`plugins/delivery-system-openai/` 是由脚本生成的本地安装包，不得手工编辑。

## 修改与构建顺序

1. 修改适用的 Core 或 canonical Adapter；
2. 审查各 Skill 的 `references/core-projection.md`，并同步 `SYNC-MANIFEST.json`；
3. 运行 `python scripts/build_openai_distribution.py` 生成 `plugins/`；
4. 运行 `python scripts/validate_v0.py` 检查结构、投影和分发包一致性；
5. 运行适用的官方 Plugin/Skill 校验器；
6. 提交 canonical 源、生成包、文档与验证证据。

禁止仅修改 `plugins/`：下一次构建会覆盖这些改动，并导致源与安装包漂移。

## 何时更新 Adapter Contract

当 Skill 映射、Core 版本、触发方式、宿主权限、审批降级、外部操作范围、安装方式或已知限制变化时，同时更新 `adapters/delivery-system-openai/ADAPTER-CONTRACT.md`。未经宿主验证的能力必须明确标为未验证，不能写成已支持。
