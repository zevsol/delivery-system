# 版本与发布维护

发布分为三条独立路线：GitHub 源码、Codex/ChatGPT 本地安装、OpenAI Plugin Directory。它们不互相替代。

每次准备发布前：更新 CHANGELOG；更新 canonical Adapter；生成 `plugins/` 分发包；运行适用校验；检查 marketplace 与文档；创建 Git 标签和 GitHub Release（依照仓库发布策略）；再按渠道发布。

OpenAI Plugin Directory 的提交条件和审核材料以当前官方文档与提交门户为准，不应从本地 marketplace 安装结果推断。
