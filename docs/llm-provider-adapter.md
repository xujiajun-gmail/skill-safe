# LLM Provider Adapter Design

> 目标：定义 `skill-safe` 中统一的 LLM 调用入口，保证 provider 可替换、调用可审计、结果不影响核心 deterministic 决策。

---

## 1. Design Goals

- 所有模型调用都走统一 client 层
- Analyzer 不直接拼 HTTP 请求
- 远端 provider 不应成为核心 admission 的单点依赖
- LLM 结果必须可审计、可回放、可引用证据

---

## 2. Usage Boundaries

允许使用 LLM 的模块：
- `alignment`
- `explain`
- `localization`

默认不允许由 LLM 单独决定的模块：
- `admission`
- `gatekeeper` 的阻断判断
- `dynamic` 的运行时拦截

---

## 3. Interface

建议抽象接口：

```python
class LLMClient(Protocol):
    def invoke(self, request: "LLMRequest") -> "LLMResponse": ...
```

### `LLMRequest`

```python
@dataclass
class LLMRequest:
    purpose: str                 # alignment | explain | localization
    prompt_version: str
    model: str
    messages: list[dict[str, str]]
    temperature: float
    max_tokens: int
    metadata: dict[str, Any]
```

### `LLMResponse`

```python
@dataclass
class LLMResponse:
    provider: str
    model: str
    prompt_version: str
    content: str
    raw_json: dict[str, Any] | None
    confidence: float | None
    token_usage: dict[str, int] | None
    latency_ms: int | None
    evidence_refs: list[str]
```

---

## 4. Provider Types

### 4.1 `openai`
- 标准远端 provider
- 通过 `base_url + api_key_env + model` 配置

### 4.2 `openai_compatible`
- 兼容 OpenAI API 的私有服务或网关
- 与 `openai` 保持统一请求形态

### 4.3 `local`
- 本地推理服务或未来本地模型适配器
- 允许无 API key 模式

---

## 5. Suggested Adapter Layer

```text
skill_safe/llm/
  base.py          # Protocol / request-response dataclasses
  client.py        # factory + routing
  providers/
    openai.py
    compatible.py
    local.py
```

---

## 6. Safety Constraints

- request 在发往远端前应经过脱敏层
- `purpose=admission` 默认禁止
- `purpose=alignment` 只传最小必要描述、配置和证据片段
- 原始 Skill 全量内容默认不直接发远端
- 所有异常应优雅降级，不能让核心扫描失败

---

## 7. Failure Handling

当 LLM 不可用时：

- `alignment`：回退到 deterministic extraction + 标注 `llm_used=false`
- `explain`：回退到模板化解释
- `localization`：回退到 message templates
- `admission`：不受影响

---

## 8. Auditability

输出应至少记录：
- `llm_used`
- `llm_provider`
- `llm_model`
- `llm_prompt_version`
- `llm_confidence`
- `evidence_refs`

并建议在调试模式保留：
- prompt hash
- request id
- latency
- token usage

---

## 9. Prompt Management

建议建立 prompt version 管理：

```text
alignment.v1
explain.v1
localization.v1
```

任何 prompt 改动都应更新版本号，以方便回归测试和结果比较。
