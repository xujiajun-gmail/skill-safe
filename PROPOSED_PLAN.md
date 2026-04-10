# skill-safe 开发计划（taxonomy-first 更新版）

## 1. Summary
- `skill-safe` 的近期目标不是做通用代码扫描器，而是做 `Skill 使用前的安全准入系统`。
- 新的工程中心不再是“多加一些规则”，而是建立一套稳定的 `taxonomy -> analyzer -> evidence -> decision` 流水线。
- `docs/skill-security-taxonomy.md` 现在应被视为单一事实来源：规则编号、测试集组织、报告字段、准入策略和后续平台治理，都围绕这套 taxonomy 收敛。
- `docs/skill-security-threat-research.md` 作为研究背景与案例库；`docs/skill-security-taxonomy.md` 作为工程规范；`PROPOSED_PLAN.md` 作为实现路线图。

## 2. Product Strategy
- 核心问题定义为：在用户或 Agent 安装、启用、升级 Skill 之前，系统能否可靠回答：
  - 它来自哪里，是否可信
  - 它声称做什么，实际上又做什么
  - 它是否会触发已知高风险 taxonomy
  - 它是否与其他 Skill/工具组成有毒调用链
  - 当前策略下是否允许运行
- 产品输出必须从“扫描报告”提升为“准入决策”：
  - `allow`
  - `review`
  - `block`
  - `sandbox_only`
- 系统输出默认支持 `中文` 和 `英文` 两种语言：
  - 根据输入内容的主语言自动选择输出语言
  - 当输入语言无法可靠判断时，默认输出 `中文`
  - 这一策略同时适用于 CLI text 输出、JSON 中的人类可读字段、`explain` 命令和后续 HTML/平台视图
- 大模型能力采用 `可选增强` 策略，而不是系统硬依赖：
  - 无大模型时，核心扫描、taxonomy 命中、policy/admission、diff/drift 必须仍可工作
  - 启用大模型时，主要增强语义分析、对齐检测、攻击链解释和多语言自然语言输出
  - 最终高风险结论和准入决策不能仅依赖模型单独给出
- 当前阶段只做 `pre-distribution audit` 和 `pre-execution admission`；可信库、分发平台和持续运营能力作为后续阶段，不抢当前实现焦点。

## 3. Canonical Threat Model
- 正式采用 8 个一级域作为主 taxonomy：
  - `EX` Execution
  - `DA` Data Access / Exfiltration
  - `MP` Memory / Persona / Workspace
  - `PI` Prompt / Instruction Manipulation
  - `SC` Supply Chain
  - `AL` Alignment
  - `CH` Chaining
  - `PR` Protocol / Runtime Environment
- 当前版本的最小覆盖目标以 `docs/skill-security-taxonomy.md` 中的 `v1 minimum coverage` 为准；任何“v1 已支持”的说法都应基于这些编号是否已稳定命中、输出和回归。
- `taxonomy_id` 必须成为系统主字段，而不是附加注释字段。

## 4. Architecture Direction
- 采用 `Core Engine + Analyzer Cluster + Meta Analyzer + Policy Engine + Admission Engine`。
- `Core Engine`
  - 负责输入归一化、任务编排、缓存、并发控制、阶段顺序和中间产物管理
  - 负责把输入解析成统一 `Skill IR` 与后续 `Capability Graph`
- `Analyzer Cluster` 按 taxonomy 映射到 4 个阶段：
  - `gatekeeper`：覆盖 `EX/DA/MP/SC/PR` 的显式风险和基础安检
  - `alignment`：覆盖 `AL`，识别 `match / over_declared / under_declared / mixed`
  - `flow`：覆盖 `CH`，并把 `PI/DA/EX` 作为 sink 风险组合进流分析
  - `dynamic`：在隔离环境中补 runtime 证据，验证显式风险和链路风险
- 在 analyzer 内部区分两类能力：
  - `deterministic analyzers`：规则、图分析、配置解析、动态观测、策略判断
  - `llm-assisted analyzers`：语义能力抽取、说明文档审查、风险解释与归纳
- `Meta Analyzer`
  - 汇总来自不同 analyzer 的 findings 和 flows
  - 做证据归并、冲突消解、重复折叠、置信度校准
  - 输出统一 `decision`
- `Policy Engine`
  - 组织策略包按 taxonomy 编排，而不是按零散规则命名
  - 支持“某些 taxonomy 默认阻断”“某些 taxonomy 在特定环境仅 sandbox_only”
- `Admission Engine`
  - 将 findings、flows、trust profile 和策略一起转成最终准入决定

## 5. Core Data Model Changes
- `Skill IR` 必须扩展为真正支撑 taxonomy 的输入，而不是只承载文件列表：
  - `provenance`: publisher, repo, release_ref, signature, hash, source channel
  - `descriptions`: README, SKILL.md, manifest text, capability labels, install instructions
  - `permissions`: files, network, shell, binaries, privilege hints
  - `sensitive_targets`: `.env`, SSH, wallet, browser data, `SOUL.md`, `MEMORY.md`, `AGENTS.md`
  - `hidden_features`: unicode tricks, high-entropy blobs, encoded payloads, hidden text regions
  - `startup_surface`: hooks, bootstrap, postinstall, local servers, MCP config
- 新增 `Capability Graph`
  - 节点：source、transform、sink、skill、tool、file、network target
  - 边：数据流、控制流、权限依赖、跨 Skill 连接关系
- 新增 `Trust Profile`
  - `publisher_confidence`
  - `provenance_status`
  - `permission_transparency`
  - `version_stability`
  - `continuous_monitoring_status`
- 新增 `Decision Record`
  - `decision`
  - `triggered_taxonomy_ids`
  - `blocked_by_policy`
  - `required_review_reason`
  - `recommended_remediation`

## 6. LLM Provider Configuration
- 如果启用大模型能力，系统必须提供统一的 `LLM provider config`，而不是把模型入口散落在各 analyzer 或脚本里。
- 配置层至少支持以下字段：
  - `mode`: `off | local | remote`
  - `provider`: 例如 `openai`、兼容 OpenAI API 的自定义服务、或本地推理服务
  - `base_url`: 模型入口地址
  - `model`: 模型名
  - `api_key_env`: API key 对应的环境变量名
  - `timeout`
  - `max_tokens`
  - `temperature`（默认建议低值，偏稳定输出）
  - `purpose_limits`: 哪些 analyzer/命令允许调用 LLM
- 推荐支持两种配置方式：
  - 配置文件，例如 `skill-safe.yml`
  - CLI 覆盖，例如 `--llm remote --llm-provider openai --llm-model gpt-5-mini`
- API key 不应直接写入扫描报告、测试样例或仓库配置文件；应优先从环境变量或系统密钥管理读取。
- 所有 LLM 请求都应通过统一 client 层发送，便于做：
  - provider 切换
  - 请求审计
  - 重试与超时控制
  - 速率限制
  - prompt version 管理
  - 后续本地模型/私有网关兼容
- 安全约束：
  - 默认不把被扫描 Skill 的完整敏感内容无条件发送给远端模型
  - 对 secrets、凭据、用户私有内容应先做脱敏或摘要化
  - 必须允许组织通过策略禁用远端 LLM，仅允许 `local` 或 `off`
  - `explain` 可用远端模型，`admission` 不应强依赖远端模型可用性

## 7. Output Contract
- JSON 是主输出格式，SARIF 作为对接格式，text 为 CLI 友好视图。
- `findings[]` 必须稳定包含：
  - `id`
  - `taxonomy_id`
  - `stage`
  - `alignment_status`（适用于 `AL-*`）
  - `severity`
  - `confidence`
  - `decision_hint`
  - `evidence[]`
  - `impact`
  - `remediation`
- `flows[]` 必须稳定包含：
  - `source_type`
  - `source_skill`
  - `transform`
  - `sink_type`
  - `sink_target`
  - `triggered_taxonomy_ids[]`
  - `blocked_by_policy`
- 顶层输出必须稳定包含：
  - `decision`
  - `trust_profile`
  - `provenance`
  - `runtime_trace`（有动态扫描时）
- 输出协议新增语言字段与约束：
  - 顶层建议增加 `output_language`
  - 所有人类可读字段（如 `title`、`impact`、`remediation`、`behavior_summary`、`decision_reason`）必须通过统一渲染层生成，而不是在规则内部写死某一种语言
  - `taxonomy_id`、`stage`、`decision`、结构化标识字段保持语言无关，避免中英文切换影响机器处理
- 当使用大模型辅助时，输出还应记录：
  - `llm_used: true|false`
  - `llm_provider`
  - `llm_model`
  - `llm_prompt_version`
  - `llm_confidence`
  - `evidence_refs`
  - 目的是保证语义分析结果可审计、可回放，而不是变成黑盒结论

## 8. CLI Evolution
- 保留：`skill-safe scan <target>`
- 近期必须新增：
  - `skill-safe validate <target>`：只检查格式、权限、策略与显式 taxonomy 命中
  - `skill-safe diff <old> <new>`：面向 `drift risk`，比较版本变化引入的 taxonomy 变化
  - `skill-safe explain <report.json>`：把 findings + flows 翻译成攻击链说明与准入理由
- CLI 语言策略：
  - 默认 `auto`
  - 支持显式参数，例如 `--lang auto|zh|en`
  - `auto` 模式优先根据输入的主要语言选择；无法判断时回退到 `zh`
- CLI 中预留 LLM 控制参数：
  - `--llm off|local|remote`
  - `--llm-provider <name>`
  - `--llm-base-url <url>`
  - `--llm-model <model>`
  - `--llm-api-key-env <env_name>`
  - 默认建议为 `off` 或 `assistive-only`，避免用户误以为系统必须联网/调用模型才能运行
- 平台化阶段预留：
  - `skill-safe trust search`
  - `skill-safe trust add`
  - `skill-safe trust list`
- 但这些平台化命令不应阻塞当前 taxonomy-first 实现。

## 9. Development Phases
- `Phase 1: Taxonomy Backbone`
  - 将 `docs/skill-security-taxonomy.md` 固化为工程主规范
  - 把当前规则系统迁移为 taxonomy-aware findings
  - 改造报告结构，引入 `taxonomy_id`、`stage`、`decision_hint`
  - 引入语言无关的 message key / template 机制，为中英文输出做准备
  - 明确 deterministic vs llm-assisted analyzer 接口边界
  - 设计统一 LLM client/config 接口，但先不强制接入远端 provider
  - 交付标准：所有当前发现都能映射到 taxonomy，而不是散乱规则名
- `Phase 2: Gatekeeper Refactor`
  - 把现有静态/语义命中重组为 `gatekeeper` analyzer
  - 先覆盖 v1 minimum coverage 中适合静态命中的 taxonomy：`EX-001`, `EX-002`, `EX-003`, `DA-001`, `PI-001`, `SC-001`, `SC-002`, `SC-003`, `PR-002`
  - 增加来源、权限、安装链、隐藏字符、品牌冒充、typosquatting、启动面检查
  - 交付标准：显式恶意和基础供应链风险可稳定输出准入建议
- `Phase 3: Policy + Admission`
  - 建立 taxonomy-aware Policy Engine
  - 每个 taxonomy 映射默认 decision，可被策略覆盖
  - 交付标准：组织可根据 taxonomy 配置 block/review/sandbox_only
- `Phase 3.5: Output Localization`
  - 建立统一渲染层，把结构化 findings/flows/decision 渲染成中英文文本
  - 实现输入主语言检测与 `--lang` 覆盖逻辑
  - 保证 JSON、text、`explain` 输出在语言上保持一致
  - 交付标准：同一份报告可稳定输出中文或英文，语言切换不影响结构化字段
- `Phase 3.6: LLM Provider Integration`
  - 实现统一 LLM client
  - 接入 provider/base_url/model/api_key_env 配置
  - 先服务 `alignment`、`explain`、`localization`，不进入 admission 决策关键路径
  - 交付标准：切换模型入口或模型名不影响整体架构与结构化输出
- `Phase 4: Alignment Detector`
  - 提取描述层能力与执行层能力
  - 输出 `AL-001/AL-002/AL-003` 与 `alignment_status`
  - 优先实现“只读声明 vs 写入行为”“无网络声明 vs 外连行为”“无执行声明 vs shell 行为”
  - 允许大模型辅助做描述层能力抽取，但最终 alignment 结论必须绑定可验证证据
  - 交付标准：能稳定识别 under-declared 风险
- `Phase 5: Capability Graph + Flow Simulator`
  - 建立 capability graph
  - 优先实现 4 条高价值链：
    - `CH-001` 不可信字符串 -> shell
    - `CH-002` 不可信字符串 -> prompt/system context
    - `CH-003` 不可信字符串 -> 敏感动作参数
    - `CH-004` secrets read -> external sink
  - 交付标准：能够识别单 Skill 低风险、组合后高风险的链式问题
- `Phase 6: Diff And Drift`
  - 实现 `diff` 子命令
  - 比较旧版/新版的 taxonomy 命中、权限变化、trust profile 变化
  - 交付标准：能回答“这次更新是否引入新的 taxonomy 风险”
- `Phase 7: Dynamic Sandbox`
  - 引入隔离执行环境
  - 挂载 honey files、fake secrets、metadata trap、localhost trap、webhook sink
  - 输出 runtime trace 并回填 findings/flows
  - 交付标准：对 `EX/DA/MP/PR` 给出行为级证据，而不是只给静态线索
- `Phase 8: Continuous Re-Scan Foundation`
  - 为未来可信库准备持续复检能力
  - 支持新版本、策略更新、威胁情报更新后复算 decision
  - 交付标准：对同一 Skill 维护稳定的 trust profile 和历史 decision 轨迹

## 10. LLM Usage Policy
- 大模型适合使用的场景：
  - 提取 README / SKILL 描述中的能力声明
  - 识别社会工程式安装说明、语义弱化、说明层欺骗
  - 聚合 findings 和 flows，生成更可读的攻击链解释
  - 提升中英文输出的自然表达质量
- 大模型不应单独决定的场景：
  - 最终 `block/allow` 准入结论
  - 高危 finding 的唯一证据来源
  - 运行时拦截或沙箱执行判断
  - “是否恶意”的唯一裁决
- 产品策略上应默认：
  - `llm disabled` 时系统仍可完成基础扫描与准入
  - `llm enabled` 时只增强 `alignment / explain / localization`
  - 所有 LLM 结果必须引用结构化证据，不能脱离上下文单独存在

## 11. Testing Plan
- 测试集按 taxonomy 目录组织，而不是按技术实现组织。
- 每个 taxonomy 至少准备：
  - `malicious/`
  - `gray/`
  - `benign/`
- 每个样本附带：
  - `expected_taxonomy_id`
  - `expected_stage`
  - `expected_decision`
  - `expected_alignment_status`（若适用）
- 近期测试重点：
  - `EX-001` 下载执行
  - `DA-001` secrets 外流
  - `MP-001` memory poisoning
  - `SC-002` 混淆与 Unicode 隐写
  - `AL-001` under-declared
  - `CH-001/CH-004` 组合攻击链
  - `PR-002` localhost / metadata access
- 语言相关测试必须覆盖：
  - 中文输入 -> 中文输出
  - 英文输入 -> 英文输出
  - 混合输入 / 语言不明显输入 -> 默认中文输出
  - 语言切换不改变 `taxonomy_id`、`decision`、`stage`、`severity` 等结构化字段
- LLM 相关测试必须覆盖：
  - `llm=off` 时核心扫描仍可运行
  - `llm=on` 时 alignment/explain 有增强但不改变结构化稳定性
  - 相同证据下，LLM 输出不能绕过 deterministic policy 决策
  - provider/base_url/model 切换后结果 schema 保持稳定
  - 缺失 `api_key_env` 时，系统应优雅降级而不是崩溃
  - 远端模型不可用时，核心扫描与 admission 仍可完成
- 回归必须按 4 类维度建立：
  - `taxonomy regression`
  - `alignment regression`
  - `flow regression`
  - `drift regression`
  - `localization regression`

## 12. Near-Term Priorities
- 现在最该做的不是 UI，不是市场前端，也不是更复杂的在线服务，而是：
  1. taxonomy-aware findings 与 report schema
  2. Gatekeeper analyzer 重构
  3. Policy/Admission 最小闭环
  4. Alignment Detector 的最小实现
  5. `diff` 子命令
- 只有当这 5 项稳定之后，再推进 capability graph、动态沙箱和持续复检，才不会让架构失焦。

## 13. Success Criteria
- 对单个 Skill：能给出稳定的 taxonomy 命中、证据、decision
- 对描述与实现：能识别至少一类高价值 `under-declared` 风险
- 对 Skill 更新：能识别新增 taxonomy 风险与权限漂移
- 对多 Skill 组合：能识别至少 2 类高价值 toxic flow
- 对治理：同一 taxonomy 在规则、报告、测试、策略中使用完全一致的编号和语义
