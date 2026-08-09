# OpenAI/Codex 发布前检查清单

本清单适用于 GitHub 源码发布与 OpenAI/Codex Adapter 发布准备。GitHub 公开、GitHub Release、本地 marketplace 安装和 OpenAI Plugin Directory 是独立渠道，任一渠道完成不代表其他渠道已发布。

## GitHub 源码与 Release

- [ ] 发布改动来自独立的 `release/*` 或 `hotfix/*` 分支，并通过 PR 合并到 `main`；
- [ ] `main` 合并后已同步回 `develop`，或已记录无需同步的原因；
- [ ] 工作区干净，`git status --short --branch` 无未预期文件；
- [ ] `python scripts/build_openai_distribution.py` 与 `python scripts/validate_v0.py` 通过；
- [ ] 官方 Plugin 与三项 Skill 校验通过；
- [ ] README、用户指南、维护指南、CHANGELOG、LICENSE、SECURITY、SUPPORT 已同步；
- [ ] 已启用 GitHub Private Vulnerability Reporting，或已在 `SECURITY.md` 公布等效私密报告渠道；
- [ ] 无 Token、真实用户数据、缓存或本地规划输入被提交；
- [ ] 真实新会话测试与已知限制已记录；
- [ ] 已完成独立发布审查；
- [ ] 已创建 Git 标签和 GitHub Release，或已记录不创建的原因。

## OpenAI Plugin Directory

GitHub 公开不等于 OpenAI 目录发布。提交前应以当时官方门户为准，确认提交资格、插件 listing、Starter Prompts、测试材料、支持/隐私/条款链接、适用国家和政策声明。本项目当前为 skills-only，不提交 MCP Server。
