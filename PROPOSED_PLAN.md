# Skill 安全审计工具 v1 计划

## Summary
- 构建一个 `CLI` 优先的 skill 安全审计工具，用于对任意来源的 skill 做高召回安全检查，输出可审计的风险报告，而不是做绝对的“安全/恶意”二元判断。
- v1 聚焦 `风险发现 + 证据归因 + 人工复核支持`，覆盖恶意迹象、无意安全缺陷、权限过度、运行时危险行为和供应链风险。
- 工具面向安全团队、技能市场审核方和平台治理团队，支持单个 skill 扫描与批量扫描，后续再演进为服务化平台。

## Key Changes
- 定义统一的 `Skill IR` 作为扫描核心输入，兼容本地目录、压缩包、Git 仓库、registry 包和 marketplace 抓取结果。
- `Skill IR` 至少包含：文件树、manifest、权限声明、命令入口、依赖、URL/域名、脚本片段、文档内容、嵌入提示、hook/MCP/tool 配置、来源元数据。
- 实现四段式扫描流水线：
  - `Ingestor`：解析输入并生成 `Skill IR`
  - `Static Engine`：规则检查、依赖与供应链分析、source-sink 图分析、权限策略检查
  - `Semantic Engine`：用 LLM 做自然语言意图审计，识别隐式越权、欺骗性包装、prompt injection/tool poisoning 痕迹
  - `Sandbox Runner`：在隔离环境中做动态分析，记录文件、进程、网络、DNS、环境变量、localhost 访问行为
- 报告模块输出 `JSON` 作为主格式，兼容 `SARIF`，并提供面向人工复核的摘要视图。
- 风险模型采用多维评分而不是单一总分，至少包含：
  - `Malice Likelihood`
  - `Exploitability`
  - `Blast Radius`
  - `Privilege Excess`
  - `Supply Chain Trust`
- v1 规则优先级固定为高价值检测，首批覆盖：
  - 越权权限声明
  - 下载执行与隐蔽执行链
  - hook/startup command/本地执行风险
  - prompt injection 与 tool poisoning 痕迹
  - 敏感文件、token、wallet、SSH 访问
  - 外流域名与第三方上传
  - localhost、内网、云 metadata 访问
  - 持久化污染到 memory/config/repo/shell profile
- 动态分析默认使用假 secrets、canary tokens、honey files 和伪内网目标，专门检测越权读取与外流。
- 判定策略保持高召回：允许误报，但每条高风险结论必须附带证据、触发原因、影响面和整改建议。

## Public Interfaces
- CLI 主命令建议为 `skill-safe scan <target>`
- v1 CLI 参数建议固定：
  - `--format json|sarif|text`
  - `--output <path>`
  - `--policy <path>`
  - `--offline`
  - `--dynamic`
  - `--source-type auto|dir|archive|git|registry`
- JSON 结果的顶层字段建议固定：
  - `target`
  - `source`
  - `summary`
  - `scores`
  - `findings`
  - `artifacts`
  - `provenance`
  - `sandbox_observations`
- `findings` 结构至少包含：
  - `id`
  - `title`
  - `severity`
  - `category`
  - `confidence`
  - `evidence`
  - `impact`
  - `remediation`

## Test Plan
- 解析测试：覆盖本地目录、zip、tar、Git 仓库和最小 manifest-only skill，确保都能稳定生成 `Skill IR`。
- 静态规则测试：为每类高优先级规则准备正例、反例、边界例，重点验证误报控制和证据定位。
- 语义审计测试：构造欺骗性 README、隐式越权说明、恶意安装引导、提示污染文本，验证模型输出能被证据约束。
- 动态分析测试：构造 benign、明显恶意、灰色风险三类样本，验证能捕获外连、读取 honey files、访问 localhost、启动子进程等行为。
- 回归测试：建立一组公开已知事件风格样本，覆盖供应链伪装、持久化污染、MCP/tool poisoning、下载执行链。
- 验收标准：
  - 单个 skill 能生成完整报告
  - 高优先级规则都有稳定输出
  - 动态扫描能拦截并记录关键行为
  - 报告可供人工快速复核
  - 不依赖“模型一句话结论”作为唯一依据

## Assumptions
- 第一版默认 `CLI 优先`，不做 SaaS 控制台、多租户、告警中心和持续监控。
- 第一版默认 `高召回优先`，接受一定误报，不以“自动判恶”作为发布门槛。
- 第一版默认扫描对象是单个 skill 或批量 skill 集合，不做完整 agent 应用全链路审计。
- 第一版默认动态分析运行在强隔离沙箱中，不允许直接在宿主机执行不可信 skill。
- 第一版默认不要求完整签名生态已存在；对 provenance 缺失做风险提示，不把“未签名”等同于“恶意”。
