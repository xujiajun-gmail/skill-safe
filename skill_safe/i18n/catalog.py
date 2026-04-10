from __future__ import annotations

import re
from typing import Any

SUPPORTED_LANGUAGES = ("zh", "en")

TAXONOMY_MESSAGES: dict[str, dict[str, dict[str, str]]] = {
    "zh": {
        "EX-001.title": "下载执行或远程代码执行风险",
        "EX-001.impact": "Skill 可能从网络拉取内容并直接在宿主执行。",
        "EX-001.remediation": "禁止下载后直接执行，并要求显式 allowlist。",
        "EX-002.title": "命令注入或动态执行风险",
        "EX-002.impact": "Skill 可能把不可信输入升级为命令或解释器执行。",
        "EX-002.remediation": "避免字符串拼接执行，改用结构化参数传递和 allowlist。",
        "EX-003.title": "高危权限或特权能力风险",
        "EX-003.impact": "Skill 请求或暴露了可能导致越权、提权或突破边界的能力。",
        "EX-003.remediation": "缩减为最小权限，并对高危能力要求显式确认。",
        "EX-004.title": "破坏性操作风险",
        "EX-004.impact": "Skill 可能执行删除、覆盖或其他不可逆修改。",
        "EX-004.remediation": "将危险写操作设为高风险并要求明确授权或隔离执行。",
        "DA-001.title": "敏感数据外流风险",
        "DA-001.impact": "Skill 可能读取敏感数据并通过网络或上传通道发送出去。",
        "DA-001.remediation": "限制高敏感目标访问并对外连目标实行严格 allowlist。",
        "DA-002.title": "用户凭据泄露风险",
        "DA-002.impact": "用户提供的 key 或 token 可能经日志、错误或上传路径泄露。",
        "DA-002.remediation": "使用安全注入与脱敏机制，避免明文输出或上报凭据。",
        "DA-003.title": "认知语境窃取风险",
        "DA-003.impact": "Skill 可能读取记忆、人格或工作流上下文等高敏感认知文件。",
        "DA-003.remediation": "默认阻断对记忆/人格文件的访问，并将其视为高敏感目标。",
        "DA-004.title": "提示或知识输入导致的数据风险",
        "DA-004.impact": "恶意 prompt、工具输出或知识库内容可能诱导系统暴露敏感数据。",
        "DA-004.remediation": "隔离不可信输入与敏感动作，并阻断危险 source-sink 路径。",
        "MP-001.title": "记忆或人格污染风险",
        "MP-001.impact": "Skill 可能向长期记忆、人格或工作流文件写入隐藏指令或偏好。",
        "MP-001.remediation": "默认阻断对记忆/人格文件的写入，并审计持久化指令修改。",
        "MP-002.title": "工作空间污染风险",
        "MP-002.impact": "Skill 可能修改工作区配置、脚本或本地配置，持续影响后续执行。",
        "MP-002.remediation": "将工作区配置和自动执行面纳入高风险审查并跟踪文件 diff。",
        "MP-003.title": "持久化后门风险",
        "MP-003.impact": "Skill 可能通过启动项、计划任务或授权文件建立持续访问能力。",
        "MP-003.remediation": "阻断持久化机制修改，并对启动面与授权文件做完整性监控。",
        "PI-001.title": "直接提示注入风险",
        "PI-001.impact": "Skill 文档、配置或输出中存在覆盖安全边界的指令模式。",
        "PI-001.remediation": "移除策略覆盖与绕过确认语言，并把不可信内容与高危动作隔离。",
        "PI-002.title": "工具输出信任升级风险",
        "PI-002.impact": "系统可能把不可信工具输出升级为可信指令或执行输入。",
        "PI-002.remediation": "禁止直接信任工具输出，并对其下游 sink 做结构化校验。",
        "SC-001.title": "供应链投毒或伪装功能风险",
        "SC-001.impact": "Skill 可能以看似正常的功能包装高风险或恶意行为。",
        "SC-001.remediation": "结合来源、权限、安装说明与行为证据进行准入审查。",
        "SC-002.title": "混淆、隐藏载荷或隐写风险",
        "SC-002.impact": "Skill 使用编码、混淆或隐藏字符掩盖真实行为。",
        "SC-002.remediation": "启用多层解码、Unicode 检测和高熵内容审查。",
        "SC-003.title": "持久化后门风险",
        "SC-003.impact": "Skill 可能通过启动项、计划任务或系统配置建立持久化访问。",
        "SC-003.remediation": "阻断持久化机制修改，并监控启动面与系统配置变更。",
        "SC-004.title": "来源、身份或信任表述风险",
        "SC-004.impact": "Skill 的身份、来源、命名或版本信息不足以支撑可信准入。",
        "SC-004.remediation": "补充 provenance、发布者身份、固定版本与可信来源信息。",
        "AL-001.title": "语义—行为不一致风险（说少做多）",
        "AL-001.impact": "Skill 的描述层低估了真实执行能力，可能误导用户或 Agent。",
        "AL-001.remediation": "对齐说明、权限与实际行为，并提升 under-declared 风险的准入等级。",
        "AL-002.title": "语义—行为不一致风险（说大做小）",
        "AL-002.impact": "Skill 声称或请求的能力超出其实际所需，增加过度授权风险。",
        "AL-002.remediation": "按最小权限原则收紧声明能力和权限范围。",
        "AL-003.title": "语义—行为混合不一致风险",
        "AL-003.impact": "Skill 的描述、权限、实现或文档叙事之间存在多处不一致。",
        "AL-003.remediation": "统一描述层与执行层叙事，并对高风险偏差做人工复核。",
        "PR-002.title": "本地、私网或 metadata 访问风险",
        "PR-002.impact": "Skill 可能访问 localhost、私网或云 metadata，触发越界访问或凭据风险。",
        "PR-002.remediation": "默认阻断 localhost、私网和 metadata 端点访问。",
        "PR-003.title": "自动启动或隐藏本地服务风险",
        "PR-003.impact": "Skill 或项目配置可能在未充分披露的情况下自动启动执行逻辑。",
        "PR-003.remediation": "要求显式用户同意，并将 startup surface 纳入隔离审查。",
        "decision.allow": "在当前规则和策略下未发现阻断级风险。",
        "decision.review": "存在需要人工复核的风险信号或语义偏差。",
        "decision.block": "命中了阻断级风险或被策略明确禁止。",
        "decision.sandbox_only": "风险不适合在宿主直接运行，仅允许运行在受限隔离环境。",
        "text.target": "目标",
        "text.source_type": "来源类型",
        "text.output_language": "输出语言",
        "text.decision": "准入结论",
        "text.findings": "问题数量",
        "text.scores": "评分",
        "text.trust_profile": "信任概况",
        "text.sandbox": "沙箱观察",
        "text.taxonomy": "分类编号",
        "text.stage": "阶段",
        "text.confidence": "置信度",
        "text.impact": "影响",
        "text.remediation": "缓解建议",
    },
    "en": {
        "EX-001.title": "Download-and-execute or remote code execution risk",
        "EX-001.impact": "The skill may fetch remote content and execute it directly on the host.",
        "EX-001.remediation": "Disallow direct execution of downloaded content and require an explicit allowlist.",
        "EX-002.title": "Command injection or dynamic execution risk",
        "EX-002.impact": "The skill may upgrade untrusted input into shell or interpreter execution.",
        "EX-002.remediation": "Avoid string-based execution and switch to structured arguments plus allowlists.",
        "EX-003.title": "Dangerous privilege or capability abuse risk",
        "EX-003.impact": "The skill requests or exposes capabilities that can cross trust boundaries or elevate privilege.",
        "EX-003.remediation": "Reduce the skill to least privilege and require explicit confirmation for dangerous capabilities.",
        "EX-004.title": "Destructive operation risk",
        "EX-004.impact": "The skill may delete, overwrite, or irreversibly modify important data.",
        "EX-004.remediation": "Treat destructive writes as high risk and require explicit authorization or sandboxing.",
        "DA-001.title": "Sensitive data exfiltration risk",
        "DA-001.impact": "The skill may read sensitive data and send it out through network or upload channels.",
        "DA-001.remediation": "Restrict high-sensitivity targets and enforce strict egress allowlists.",
        "DA-002.title": "User credential leakage risk",
        "DA-002.impact": "User-supplied keys or tokens may leak through logs, errors, or upload paths.",
        "DA-002.remediation": "Use secure injection and redaction, and avoid printing or reporting credentials in plaintext.",
        "DA-003.title": "Cognitive context theft risk",
        "DA-003.impact": "The skill may read memory, persona, or workflow context files that contain highly sensitive context.",
        "DA-003.remediation": "Block access to memory/persona files by default and treat them as high-sensitivity targets.",
        "DA-004.title": "Data risk via prompt or knowledge input abuse",
        "DA-004.impact": "Malicious prompts, tool outputs, or knowledge-base content may coerce the system into exposing sensitive data.",
        "DA-004.remediation": "Isolate untrusted input from sensitive actions and block dangerous source-sink paths.",
        "MP-001.title": "Memory or persona poisoning risk",
        "MP-001.impact": "The skill may write hidden instructions or preferences into long-lived memory, persona, or workflow files.",
        "MP-001.remediation": "Block writes to memory/persona files by default and audit persistent instruction changes.",
        "MP-002.title": "Workspace poisoning risk",
        "MP-002.impact": "The skill may modify workspace config, scripts, or local settings and persistently affect later execution.",
        "MP-002.remediation": "Treat workspace config and auto-run surfaces as high risk and track file diffs.",
        "MP-003.title": "Persistence backdoor risk",
        "MP-003.impact": "The skill may establish continued access via startup items, scheduled tasks, or authorization files.",
        "MP-003.remediation": "Block persistence changes and monitor startup surfaces and authorization files for integrity.",
        "PI-001.title": "Direct prompt injection risk",
        "PI-001.impact": "The skill contains instruction patterns that attempt to override safety boundaries.",
        "PI-001.remediation": "Remove policy-override language and isolate untrusted content from dangerous actions.",
        "PI-002.title": "Untrusted tool-output upgrade risk",
        "PI-002.impact": "The system may upgrade untrusted tool output into trusted instructions or execution input.",
        "PI-002.remediation": "Never trust tool output directly and validate any downstream sink structurally.",
        "SC-001.title": "Supply-chain poisoning or disguised-functionality risk",
        "SC-001.impact": "The skill may package risky or malicious behavior behind apparently normal functionality.",
        "SC-001.remediation": "Review provenance, permissions, install guidance, and behavior evidence before admission.",
        "SC-002.title": "Obfuscation, hidden payload, or steganographic risk",
        "SC-002.impact": "The skill uses encoding, obfuscation, or hidden characters to conceal its real behavior.",
        "SC-002.remediation": "Enable multi-layer decoding, Unicode inspection, and high-entropy content review.",
        "SC-003.title": "Persistence backdoor risk",
        "SC-003.impact": "The skill may establish persistence via startup items, scheduled tasks, or system configuration.",
        "SC-003.remediation": "Block persistence mechanisms and monitor startup surfaces and system configuration changes.",
        "SC-004.title": "Origin, identity, or trust-representation risk",
        "SC-004.impact": "The skill's identity, provenance, naming, or versioning is not strong enough for trusted admission.",
        "SC-004.remediation": "Add provenance, publisher identity, pinned versions, and trustworthy source metadata.",
        "AL-001.title": "Semantic-behavior misalignment risk (under-declared)",
        "AL-001.impact": "The skill's description understates its real execution capability and may mislead users or agents.",
        "AL-001.remediation": "Align the description, permissions, and actual behavior, and escalate under-declared risks.",
        "AL-002.title": "Semantic-behavior misalignment risk (over-declared)",
        "AL-002.impact": "The skill claims or requests more capability than it actually needs, increasing over-permission risk.",
        "AL-002.remediation": "Tighten declared capability and permissions under least-privilege principles.",
        "AL-003.title": "Mixed semantic-behavior misalignment risk",
        "AL-003.impact": "The skill's descriptions, permissions, implementation, or docs disagree in multiple ways.",
        "AL-003.remediation": "Unify the description and execution narrative and manually review high-risk deviations.",
        "PR-002.title": "Localhost, private-network, or metadata access risk",
        "PR-002.impact": "The skill may access localhost, private-network, or cloud metadata endpoints and cross trust boundaries.",
        "PR-002.remediation": "Block localhost, private-network, and metadata access by default.",
        "PR-003.title": "Auto-start or hidden local-service risk",
        "PR-003.impact": "The skill or project config may auto-start execution logic without sufficient disclosure.",
        "PR-003.remediation": "Require explicit user consent and review startup surfaces inside isolation.",
        "decision.allow": "No blocking-risk issue was found under the current rules and policy.",
        "decision.review": "The scan found issues that require human review or semantic clarification.",
        "decision.block": "The scan hit a blocking-risk category or a policy-prohibited condition.",
        "decision.sandbox_only": "The skill is not suitable for direct host execution and should only run in restricted isolation.",
        "text.target": "Target",
        "text.source_type": "Source type",
        "text.output_language": "Output language",
        "text.decision": "Decision",
        "text.findings": "Findings",
        "text.scores": "Scores",
        "text.trust_profile": "Trust profile",
        "text.sandbox": "Sandbox observations",
        "text.taxonomy": "Taxonomy",
        "text.stage": "Stage",
        "text.confidence": "Confidence",
        "text.impact": "Impact",
        "text.remediation": "Remediation",
    },
}



def supported_languages() -> tuple[str, ...]:
    return SUPPORTED_LANGUAGES



def render_message(language: str, key: str, **params: Any) -> str:
    language = language if language in SUPPORTED_LANGUAGES else "zh"
    template = TAXONOMY_MESSAGES.get(language, {}).get(key)
    if template is None:
        template = TAXONOMY_MESSAGES["zh"].get(key, key)
    if params:
        try:
            return template.format(**params)
        except Exception:
            return template
    return template



def detect_language(text: str | None, requested: str = "auto") -> str:
    if requested in {"zh", "en"}:
        return requested
    if not text:
        return "zh"
    chinese = len(re.findall(r"[\u4e00-\u9fff]", text))
    latin = len(re.findall(r"[A-Za-z]", text))
    if chinese == 0 and latin == 0:
        return "zh"
    if chinese >= latin / 2:
        return "zh"
    return "en"
