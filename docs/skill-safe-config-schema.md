# skill-safe Config Schema

> 目标：定义 `skill-safe.yml` 的首版配置结构，覆盖扫描行为、策略、语言、多语言输出、LLM provider 和运行时安全约束。

---

## 1. Design Principles

- 配置应优先服务本地 CLI 与未来 CI 场景
- 所有配置都应有明确默认值
- 敏感值不直接写入配置文件，优先使用环境变量引用
- 配置结构要支持后续平台化，但当前不引入不必要的复杂层级

---

## 2. Recommended File Name

推荐优先查找：

```text
skill-safe.yml
skill-safe.yaml
.skill-safe.yml
```

解析优先级建议：

1. CLI 参数覆盖
2. 项目本地配置文件
3. 用户级配置文件（未来）
4. 默认值

---

## 3. Schema Overview

```yaml
version: 1

scan:
  source_type: auto
  include_hidden: true
  follow_symlinks: false
  max_file_size_kb: 5120
  max_archive_size_mb: 100
  enable_diff: true
  enable_dynamic: false

language:
  mode: auto
  default: zh
  supported:
    - zh
    - en

output:
  format: text
  include_evidence_excerpt: true
  include_runtime_trace: true
  include_llm_metadata: true

policy:
  profile: default
  allow_unsigned: false
  allow_shell: false
  allow_private_network: false
  allow_localhost: false
  allow_metadata_access: false
  allow_memory_file_write: false
  allow_startup_hooks: false
  taxonomy_overrides: {}

llm:
  mode: off
  provider: openai
  base_url: https://api.openai.com/v1
  model: gpt-5-mini
  api_key_env: OPENAI_API_KEY
  timeout_seconds: 30
  max_tokens: 1200
  temperature: 0.1
  purpose_limits:
    alignment: true
    explain: true
    localization: true
    admission: false
    gatekeeper: false

dynamic:
  provider: sandbox_stub
  network_mode: blocked
  enable_honeyfiles: true
  enable_fake_secrets: true
  enable_metadata_trap: true
  enable_localhost_trap: true

telemetry:
  enabled: false
  redact_paths: true
  redact_env_values: true
```

---

## 4. Field Definitions

### 4.1 `version`
- 类型：`int`
- 必填：是
- 当前固定：`1`

### 4.2 `scan`
- `source_type`: `auto|dir|archive|git`
- `include_hidden`: 是否扫描隐藏文件
- `follow_symlinks`: 默认 `false`
- `max_file_size_kb`: 单文件最大扫描体积
- `max_archive_size_mb`: 压缩包最大处理体积
- `enable_diff`: 是否允许 `diff` 流程复用配置
- `enable_dynamic`: 是否允许动态阶段执行

### 4.3 `language`
- `mode`: `auto|zh|en`
- `default`: 语言判断不清时的回退值，当前固定建议 `zh`
- `supported`: 允许的输出语言列表

### 4.4 `output`
- `format`: `text|json|sarif`
- `include_evidence_excerpt`: 是否输出证据片段
- `include_runtime_trace`: JSON/text 是否包含运行时痕迹摘要
- `include_llm_metadata`: 是否输出模型元数据

### 4.5 `policy`
- `profile`: `default|strict|permissive|<custom>`
- `allow_unsigned`: 是否允许未签名/无 provenance Skill 直接通过
- `allow_shell`: 是否允许 shell 能力被直接放行
- `allow_private_network`: 是否允许私网访问
- `allow_localhost`: 是否允许 localhost/127.0.0.1
- `allow_metadata_access`: 是否允许 metadata endpoint
- `allow_memory_file_write`: 是否允许写 `MEMORY.md` / `SOUL.md` / `AGENTS.md`
- `allow_startup_hooks`: 是否允许 bootstrap/postinstall/startup hooks
- `taxonomy_overrides`: 对具体 taxonomy 做策略覆盖

示例：

```yaml
policy:
  profile: strict
  taxonomy_overrides:
    EX-004: review
    AL-002: review
    PR-002: block
```

### 4.6 `llm`
- `mode`: `off|local|remote`
- `provider`: provider 名称，如 `openai`、`openai_compatible`、`local_ollama`
- `base_url`: provider 入口
- `model`: 模型名
- `api_key_env`: API key 读取的环境变量名
- `timeout_seconds`
- `max_tokens`
- `temperature`
- `purpose_limits`: 哪些模块允许调用 LLM

### 4.7 `dynamic`
- `provider`: 当前执行后端，如 `sandbox_stub`、`docker`、`firecracker`（未来）
- `network_mode`: `blocked|allowlist|open`
- `enable_honeyfiles`
- `enable_fake_secrets`
- `enable_metadata_trap`
- `enable_localhost_trap`

### 4.8 `telemetry`
- 默认关闭
- 后续如启用，也必须默认脱敏

---

## 5. CLI Override Mapping

建议支持以下 CLI 覆盖：

```text
--lang auto|zh|en
--format text|json|sarif
--dynamic
--policy-profile strict
--llm off|local|remote
--llm-provider <name>
--llm-base-url <url>
--llm-model <model>
--llm-api-key-env <env>
```

CLI 优先级高于配置文件。

---

## 6. Validation Rules

- `language.default` 必须属于 `language.supported`
- `llm.mode=remote` 时必须提供 `provider`、`base_url`、`model`、`api_key_env`
- `llm.purpose_limits.admission` 默认必须为 `false`
- 若 `policy.allow_private_network=false`，则 `PR-002` 默认至少为 `block`
- 若 `dynamic.network_mode=blocked`，动态阶段不得主动访问外网

---

## 7. Recommended Minimal Config

```yaml
version: 1

language:
  mode: auto
  default: zh

policy:
  profile: strict
  allow_shell: false
  allow_private_network: false
  allow_localhost: false
  allow_metadata_access: false

llm:
  mode: off
```
