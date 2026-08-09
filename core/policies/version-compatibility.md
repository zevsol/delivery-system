# 版本与兼容政策

Core Contract、Schema、canonical Adapter 和生成分发包必须各自声明或可追溯其版本。

- **Patch**：不改变产物语义的澄清、文档或错误修正；
- **Minor**：向后兼容的规则、模板、可选字段或场景增加；
- **Major**：改变角色边界、Artifact 含义、必填关系或 Adapter 行为的破坏性变更。

Core 发生语义变更时，维护者必须评估每个 Adapter 的受控投影、Schema、模板、Conformance 场景和生成分发包。Adapter 只有在更新其 `coreVersion` 并完成适用一致性检查后，才能宣称支持新 Core 版本。

对于不兼容的 Schema 变更，必须提供迁移说明或明确标记旧产物继续适用的边界。不得以覆盖旧文件的方式静默改变用户项目产物。
