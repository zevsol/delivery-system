# Delivery System Core Contract

> 状态：Draft v0.1 / Phase 1 审查稿
>
> 权威范围：Delivery System 的平台无关交付语义
> 不包含：任何平台的 manifest、Skill/Agent 文件格式、安装方式或工具私有配置

## 1. 目的与权威性

Delivery System Core 定义软件交付流程中的稳定语义：角色、工作流、策略、产物、追踪关系、质量门和一致性规则。

`core/` 是这些语义的唯一事实来源（Single Source of Truth）。任何平台适配器都必须保留本契约的含义，不能自行定义另一套角色权限、Issue 粒度、变更流程、质量门或产物格式。

Core 只规定“必须作出的决策、必须保留的证据和必须满足的治理结果”；它不规定用户界面、提示词语法、文件扩展名、平台安装路径或某项工具调用方式。

## 2. 规范用语

本契约中的关键词按以下强度解释：

- **必须（MUST）**：不满足即不符合 Core。
- **不得（MUST NOT）**：禁止的行为。
- **应当（SHOULD）**：默认要求；偏离时应记录原因和影响。
- **可以（MAY）**：可选能力，不影响基本符合性。
- **TBD / Requires verification**：尚未由权威信息确认，不能被当作已支持的能力。

## 3. Core 范围

Core 由以下五类内容组成：

```text
core/
├── workflows/       角色如何推进交付阶段
├── policies/        所有角色共同遵守的治理规则
├── schemas/         机器可读的稳定产物结构
├── templates/       可按项目规模裁剪的产物模板
└── conformance/     行为与语义一致性规则
```

Core 不直接连接 GitHub、Linear、Jira、文档系统或 MCP Server。外部系统连接属于 Optional Tool Layer；宿主平台对工具、权限、审批与安装的支持属于 Platform Adapter。

## 4. 核心角色

| Core Role / Workflow | 主要责任 | 不得做的事 |
|---|---|---|
| Idea to Delivery | 发现、规划、分解、维护基线和协调变更 | 自行宣称独立审查通过；虚构关键决定；未经批准扩大范围 |
| Audit Delivery | 独立、只读地检查证据、覆盖、风险和漂移 | 直接修改产物或代码；自行接受建议；替用户决定范围 |
| Execute Delivery | 按已批准、无阻塞的 Issue 实现并提供验证证据 | 擅自改变产品目标、扩大 Issue 或跳过验收标准 |
| User / Product Owner | 对产品目标、范围、关键架构、重大风险和发布作最终决定 | 将未确认决定表示为已批准 |

具体平台可以将前三者映射为 Skill、Agent、Rule、Command 或 CLI 子命令，但映射不得改变以上责任和禁止事项。

## 5. 交付状态机

Core 的默认交付阶段如下；小修复或低风险工作可以裁剪阶段，但不得绕过适用的阻塞、审批或验证要求。

```text
Intake
→ Discovery
→ Requirements
→ Architecture / Feasibility
→ Roadmap
→ Decomposition
→ Independent Audit
→ Approval
→ Execution
→ Verification
→ Change Management（按需进入并重新建立基线）
→ Closure
```

产物或 Issue 必须声明其状态。推荐状态：`draft`、`proposed`、`approved`、`active`、`blocked`、`deferred`、`superseded`、`completed`、`closed`。适配器可映射为平台自己的状态名称，但不得丢失其语义。

## 6. Artifact Envelope

每个正式产物必须具有足以追溯其来源、状态与影响范围的最小元数据。Markdown、JSON、Issue 系统字段或其他平台表示均可，前提是可恢复下列语义：

```text
Artifact
├── id: 稳定唯一标识
├── type: 产物类型
├── title: 人类可读标题
├── status: 生命周期状态
├── owner: 负责角色或明确责任人
├── source: 上游需求、决策、风险或维护目标
├── relationships: 依赖、覆盖、替代、阻塞和关联关系
├── baseline: 所属基线或版本
├── decisionRecord: 必要时的用户决定与日期
├── evidence: 验证或审查证据
└── changeHistory: 对正式基线的关键变更
```

Core 允许按规模裁剪非关键字段；但 `id`、`type`、`status`、可追溯来源和必要关系不可省略。未知信息必须标为 `Unknown`、`TBD` 或 `Blocked`，不得以猜测填充。

## 7. 标识与追踪

正式产物使用稳定编号。首版标准前缀如下；小型项目可以省略 `MILE-` 与 `FEAT-`，但不能破坏既有关系的可追溯性：

```text
IDEA-001  原始意图或已确认的 Idea
REQ-001   功能或业务需求
NFR-001   非功能需求
ADR-001   架构决策记录
MILE-001  Milestone
EPIC-001  Epic
FEAT-001  Feature / Capability
ISSUE-001 可独立交付工作项
TEST-001  测试或验证项
CHG-001   Change Request
FINDING-001 审查发现
SPIKE-001 调查或风险消减任务
```

最低追踪规则：

- 每个正式 Requirement 必须由一个或多个 Issue 覆盖，或明确标为 `deferred` / `rejected` 并记录决定。
- 每个 Issue 必须追溯到 Requirement、ADR、风险、缺陷或明确维护目标之一。
- 每个关键验收标准必须关联验证方法或 Test Evidence。
- 修改或删除上游产物时，必须评估下游关系并创建必要的 Change Request、替代关系或重新基线记录。
- 不允许无来源的孤儿 Issue，也不允许没有执行计划的孤儿承诺需求。

## 8. Issue Contract

Issue 是可独立交付、可独立验证、可独立评审的结果，不是文件操作列表。

每个可执行 Issue 至少必须包含：背景、目标、范围、非目标、实施约束、依赖、验收标准、验证方法、Definition of Done，以及关联 Requirement / ADR / 风险。

一个 Issue 达到可执行粒度时，必须同时满足：

1. 只有一个主要交付结果；
2. 验收标准可观察、可验证；
3. 依赖和阻塞状态明确；
4. 不跨越不相关职责边界；
5. 失败时可以定位原因；
6. 不需要等待整个 Epic 完成才能验证；
7. 未知技术风险已通过 Spike 处理，或 Issue 明确为 blocked。

`XL` Issue 不得直接进入执行；必须进一步拆分或先创建 Spike。时间估算可作为辅助信息，但不得作为唯一粒度标准。

## 9. Implementation Ready 与 Definition of Done

### Implementation Ready

Issue 只有在以下条件满足时才可交给 Execute Delivery：

- 问题、目标用户和主要场景足够明确；
- 范围与非目标明确；
- 关键需求与验收标准可验证；
- 必要的架构决定已被接受，或未知项已明确阻塞；
- 依赖已识别且满足进入执行的条件；
- 变更影响已同步到相关产物；
- Issue 已获得所需批准。

缺少关键决定时，Idea to Delivery 必须输出 Clarification Request、Research Task、Spike、ADR Decision Required 或 Blocked Issue，而不是假定答案后推进。

### Definition of Done

Issue 完成必须至少具备：实现证据、适用测试或验证证据、每条验收标准的对照结果、直接相关技术文档更新、已知未验证内容和剩余风险。完成不等于产品验收通过；产品验收由 User / Product Owner 决定。

## 10. Baseline 与 Change Management

Baseline 是一组在某一时点已批准并共同生效的 Requirement、ADR、Roadmap、Issue 与相关验证承诺。

新需求、重大澄清、架构变化、范围扩张、技术发现和紧急阻塞必须先被记录并分类。除非同时满足“不改变目标、不产生新用户能力、不显著扩大测试范围、不改变架构或依赖、仍可按原验收标准闭环”，否则不得静默混入进行中的 Issue。

Change Request 最少应包含：新需求原文、触发原因、分类、受影响产物、范围/成本/风险影响、可选方案、推荐、用户决定和生效基线。获批准的 Change Request 必须更新源头产物及所有必要下游关系。

## 11. 审查、审批与证据

Audit Delivery 必须只读，并使用可复查证据形成 Finding。每项 Finding 至少包含：ID、严重度、类别、证据、影响、建议、受影响产物和所需决定。

Finding 的建议不会自动修改正式基线。User / Product Owner 对每项重要 Finding 作出 `accept`、`reject`、`defer` 或 `need clarification` 决定后，Idea to Delivery 才可以修订相应产物。

Core 要求适配器能表达以下最低审批语义：

- 产品范围和关键架构决策需要明确批准；
- 重大审查意见需要用户决定；
- 批量外部写入、发布、删除和其他不可逆操作需要用户确认；
- 适配器无法提供交互审批时，必须降级为生成预览、草稿或阻塞状态。

## 12. Platform Adapter Contract

每个 Adapter 必须单独声明并版本化以下内容：

- `adapterId` 与目标平台；
- 支持的 `coreVersion`；
- 已映射的 Core Role / Workflow；
- 触发方式；
- 可用工具、文件读写能力和限制；
- 审批机制与不可用时的降级策略；
- 外部操作和 MCP 支持范围；
- 安装与分发方式；
- 已知限制；
- conformance test 结果与未覆盖情形。

适配器可以改变语言、界面和文件布局，但不得改变 Core 的关键决策、角色权限、阻塞条件、产物关系或批准要求。

若适配器因平台限制不能保留某项 Core 语义，必须：

1. 明确声明不符合或部分符合的条款；
2. 提供安全降级策略；
3. 不把缺失能力伪装成已实现；
4. 在 conformance test 中记录该限制。

## 13. Conformance

Core Behavior Tests 是平台无关的标准场景。所有 Adapter 都应使用等价输入验证以下不可变结果：

- 模糊 Idea 进入 Discovery，而非直接实现；
- 关键条件缺失时停止并输出适当阻塞产物；
- 项目规模与流程深度合理匹配；
- Issue 按独立结果拆分；
- 新需求进入 Change Management；
- Auditor 保持只读；
- Executor 不扩大 Issue 范围；
- Requirement、ADR、Issue 和验证证据保持追踪。

Adapter Conformance Tests 验证平台映射结果。允许表达方式不同，但不允许上述治理语义不同。Platform-specific Integration Tests 则验证平台实际的安装、触发、权限和工具行为，不能替代 Conformance Tests。

## 14. 版本与变更规则

Core Contract 使用语义化版本原则：

- 主版本：破坏现有 Artifact 或 Adapter 语义的变更；
- 次版本：向后兼容的新产物、规则或可选字段；
- 修订版本：澄清、示例和不改变语义的修正。

变更 Core Contract 必须记录动机、受影响的 Schema/模板/测试、Adapter 影响和迁移策略。适配器必须声明其支持的 Core 版本；不兼容时不得声称完全符合。

## 15. Phase 1 已确认决策与待决事项

已确认：

- 使用 MIT License；
- 首版 Core 文档只维护中文；多语言维护作为后续范围；
- 小型项目允许省略 `MILE-` 与 `FEAT-` 编号；
- 首个 Git 提交包含项目骨架与已审查的 Core Contract；本地规格源文档和 `temp.txt` 不纳入版本控制。

仍待后续设计确认：

- Artifact Schema 的具体 JSON Schema 版本与校验工具，待确定性校验需求明确后决定；
- 公开支持渠道、漏洞报告地址和发布平台，待公开发布规划阶段决定。
