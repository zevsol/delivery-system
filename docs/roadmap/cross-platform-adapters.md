# 跨平台 Adapter 路线

Core 的目标是跨平台一致的交付语义，而不是一次性支持所有宿主。

## 推荐顺序

1. 完成 OpenAI/Codex 的真实场景验证；
2. 选择一个第二平台；
3. 查询该平台当前官方格式、触发、权限、文件访问和分发机制；
4. 编写该 Adapter Contract；
5. 使用相同 Core Conformance 场景验证；
6. 记录能力差异和安全降级；
7. 再考虑下一个平台。

Claude、Cursor、Generic Agent、CLI 目前均未实现。不得把 OpenAI 的 Skill 文件复制后宣称兼容；每个平台需要自己的 Adapter 和一致性证据。
