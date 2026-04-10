# i18n And Message Template Design

> 目标：让 `skill-safe` 的中英文输出稳定、可测试、与结构化字段解耦。

---

## 1. Principles

- 结构化字段语言无关
- 文本输出走统一渲染层
- 默认支持 `zh`、`en`
- 输入语言判断不清时默认 `zh`

---

## 2. What Must Stay Language-Neutral

以下字段不得随语言变化：

- `taxonomy_id`
- `stage`
- `decision`
- `severity`
- `alignment_status`
- `source_type`
- `triggered_taxonomy_ids`

这些字段必须是稳定枚举值。

---

## 3. What Is Localized

以下字段通过 message template 渲染：

- `title`
- `impact`
- `remediation`
- `behavior_summary`
- `decision_reason`
- `flow_summary`

---

## 4. Message Key Strategy

建议 message key 与 taxonomy / decision 解耦但可组合：

```text
finding.title.EX-001
finding.impact.EX-001
finding.remediation.EX-001
alignment.summary.under_declared
decision.reason.block
flow.summary.CH-001
```

---

## 5. Suggested Directory Layout

```text
docs/
config/
messages/
  zh.yml
  en.yml
```

或代码内：

```text
skill_safe/i18n/
  catalog.py
  messages/
    zh.yml
    en.yml
```

---

## 6. Example Templates

### `zh.yml`

```yaml
finding:
  title:
    EX-001: "下载执行或远程代码执行风险"
  impact:
    EX-001: "Skill 可能从网络拉取内容并直接在宿主执行。"
  remediation:
    EX-001: "禁止下载后直接执行，并要求显式 allowlist。"

decision:
  reason:
    block: "命中了阻断级风险或策略禁止项。"
```

### `en.yml`

```yaml
finding:
  title:
    EX-001: "Download-and-execute or remote code execution risk"
  impact:
    EX-001: "The skill may fetch remote content and execute it on the host."
  remediation:
    EX-001: "Disallow direct execution of downloaded content and require an explicit allowlist."

decision:
  reason:
    block: "The scan hit a blocking-risk category or a disallowed policy condition."
```

---

## 7. Language Selection Policy

- `--lang zh`：强制中文
- `--lang en`：强制英文
- `--lang auto`：根据输入主语言判断
- 无法可靠判断时：回退 `zh`

建议语言判断依据：
- README / SKILL.md / manifest description 中的主要自然语言
- 用户 CLI 参数覆盖优先

---

## 8. Rendering Rules

- Rule/analyzer 只输出结构化字段与 message key 所需参数
- Renderer 负责根据 `output_language` 渲染最终文本
- LLM 可以增强 explain 文本，但不能替代基本模板系统

---

## 9. Testing Requirements

- 中文输入 -> 中文输出
- 英文输入 -> 英文输出
- 混合输入 -> 默认中文
- 语言切换不改变结构化 schema
