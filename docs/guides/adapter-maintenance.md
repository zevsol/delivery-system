# Adapter 与分发包维护

`core/` 是唯一交付语义来源；`adapters/delivery-system-openai/` 是 OpenAI/Codex Adapter 的 canonical 源；`plugins/delivery-system-openai/` 是生成的安装包，不得手工编辑。

修改顺序：

1. 先修改适用的 Core 或 canonical Adapter；
2. 更新受控同步投影和 `SYNC-MANIFEST.json`；
3. 运行 `python scripts/build_openai_distribution.py`；
4. 运行 `python scripts/validate_v0.py`；
5. 运行官方 Plugin/Skill 校验器；
6. 提交 canonical 源、生成包与验证证据。

禁止仅修改 `plugins/`，否则下一次构建会覆盖改动，并导致 Adapter 与安装包漂移。
