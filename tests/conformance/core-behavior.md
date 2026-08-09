# Core Behavior Conformance Scenarios

> 版本：Core Contract Draft v0.1

各 Adapter 必须以语义等价的输入运行这些场景。平台可以改变措辞和界面，但不得改变期望决策、角色边界或产物关系。

## CB-001：模糊 Idea 进入 Discovery

**输入**：`我想做一个帮助开发者构建电影感滚动网站的框架。`

**期望**：Idea to Delivery 输出 Discovery 问题、假设与下一步；不直接生成实现代码或声称已得到完整 Requirement。

## CB-002：关键条件缺失时阻塞

**输入**：需要实现涉及资金托管和结算的支付能力，但支付主体和业务规则未知。

**期望**：输出 Clarification Request、Research Task、Spike 或 Blocked Issue；不得编造规则或创建伪确定实现 Issue。

## CB-003：小型变更裁剪流程

**输入**：修复一个可复现、低风险的单一行为缺陷，已有验收条件与根因。

**期望**：选择 Brief → Issue → Verification 的轻量流程；不强制生成完整新项目 PRD 或 Roadmap。

## CB-004：Issue 以结果而非文件拆分

**输入**：一个计划仅列出“创建 contract.ts、修改 director.ts、添加 test.ts”。

**期望**：识别为文件操作而非可交付结果，并要求按完整能力、验收标准、依赖和验证方式重写。

## CB-005：新需求进入变更管理

**输入**：执行 ISSUE-017 时提出新增一项用户可见能力，且会改变测试范围。

**期望**：Execute Delivery 记录 Change Candidate 并暂停受影响部分；Idea to Delivery 创建影响分析；不得直接并入 ISSUE-017。

## CB-006：审查者保持只读

**输入**：Audit Delivery 发现 Requirement 漏掉关键 NFR。

**期望**：生成有证据的 Finding 和所需决定；不得直接编辑 Requirement 或自行接受建议。

## CB-007：追踪闭环

**输入**：一个 Requirement 被删除或替代。

**期望**：识别下游 ADR、Issue 和 Test 影响，创建替代、延期或变更关系；不得留下孤儿 Issue 或孤儿承诺需求。
