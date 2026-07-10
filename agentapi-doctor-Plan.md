# AgentAPI Doctor：成熟开源项目完整实施计划

> 设计计划版本：1.0-draft（实施前基线，不代表项目已达到 v1.0）  
> 调研基线：2026-07-10  
> 项目阶段：立项与架构设计  
> 目标：建设一个可长期维护、可被上游 CI 采用、能产出可信公共兼容矩阵的 Agentic LLM API 兼容性实验室，而非接口探活器、Demo 或一次性 Benchmark。

---

## 0. 执行摘要

### 0.1 最终定位

工作名：**AgentAPI Doctor**，仓库暂定 **agentapi-doctor**。

英文定位：

> AgentAPI Doctor is a client-observed compatibility laboratory for agentic LLM APIs. It tells you whether real SDKs and agents can reliably complete tool-use workflows through an endpoint, and produces evidence showing where a failure originates.

中文定位：

> 面向真实 SDK 与 Agent 客户端的多协议兼容实验室：不仅检查 HTTP/JSON/SSE 字段，还运行真实工具调用链，区分协议实现、模型行为、SDK 解析和 Agent 编排故障，并生成上游可直接使用的最小复现。

项目必须回答五个互不替代的问题：

1. Transport 是否正确：HTTP、TLS、SSE、WebSocket、超时、取消、错误和重试。
2. Protocol 是否正确：Schema、事件状态机、ID/index 关联、tool call/result 语义。
3. Model 是否具备能力：是否选择正确工具、生成正确参数、完成多轮工具流程。
4. Client 是否兼容：指定版本的 SDK、Codex、OpenClaw、Vercel AI SDK 能否实际消费。
5. 运行是否可靠：重复运行的稳定性、flakiness、429/5xx、延迟和资源释放。

### 0.2 项目最重要的战略边界

- 不做 LLM Gateway、代理、路由、模型聚合或计费平台。
- 不重新制定 OpenAI、Anthropic、Google 或 MCP 规范。
- 不把模型回答质量与 wire conformance 混成一个总分。
- 不把任意官方 SDK 当作协议真理；SDK 自身也是被测客户端。
- 不执行真实支付、邮件、数据库等副作用工具；全部使用合成工具和隔离环境。
- 不宣称获得任何厂商官方认证；公开结果使用 “Verified against” 或 “Observed compatible with”。
- 不将 Embeddings、图像生成、Realtime Audio 等能力作为 Agent-ready 核心门槛。

### 0.3 为什么值得做

真实问题已经从“接口能否返回文本”转变为“完整 Agent tool loop 能否被真实客户端消费”：

- vLLM 的 Responses streaming 曾因一个 delta 中出现多个工具调用而触发断言并终止连接：[vLLM #39584](https://github.com/vllm-project/vllm/issues/39584)。
- llama.cpp 的 Responses SSE 曾缺失 Vercel AI SDK 必需的 output index 等字段，导致事件被静默丢弃：[llama.cpp #20607](https://github.com/ggml-org/llama.cpp/issues/20607)。
- LiteLLM 的 Snowflake streaming 会静默丢失 tool calls，而普通文本 streaming 正常：[LiteLLM #30762](https://github.com/BerriAI/litellm/issues/30762)。
- vLLM 2026 年仍出现 Responses streaming 的 content index 错误导致 OpenAI SDK 崩溃：[vLLM #45742](https://github.com/vllm-project/vllm/issues/45742)。
- LLM-Rosetta 论文明确指出，除 Open Responses 外，其他主流 provider wire format 缺少独立维护的综合 conformance corpus：[LLM-Rosetta §6.5](https://arxiv.org/html/2604.09360v1)。

OpenAI 官方已把 Responses 定位为 Agent 开发的未来方向，且提醒迁移者正确处理 typed items、call ID、state 和 typed streaming events：[Responses 迁移指南](https://developers.openai.com/api/docs/guides/migrate-to-responses)。Codex 当前自定义 Provider 的 wire API 只支持 Responses，因此 “Codex compatible” 必须是严格的 Responses profile，而不是 Chat Completions 的近似替代：[Codex 配置参考](https://developers.openai.com/codex/config-reference)。

### 0.4 竞争现实与立项条件

该方向已存在早期直接竞品：

- [am-i-openai-compatible](https://github.com/heiervang-technologies/am-i-openai-compatible)：探针、GitHub Action 和开源推理服务矩阵。
- [openai-compatible-tester-cli / octest](https://github.com/ibidathoillah/openai-compatible-tester-cli)：Chat、SSE、tools、structured output、embeddings、错误与 CI；其 roadmap 已包括 SDK 模式和兼容矩阵。
- [FauxpenAI-conformance](https://github.com/aliok/FauxpenAI-conformance)：参考 OpenAI 与自定义端点的差分比较。
- [Open Responses](https://github.com/openresponses/openresponses)：Responses 风格的开放规范及 compliance suite。

因此，新项目只有同时做到以下四点才值得独立建仓：

1. 多协议且规范可追溯，而不只是 OpenAI Chat 探针。
2. 真实 SDK/Agent client profile 是核心产品，不是 roadmap 附件。
3. 具备自动故障域定位、失败最小化和上游 Issue Bundle。
4. 具备签名、不可变、带 freshness 的公共兼容观察注册表。

立项第一周必须联系上述四个相关项目，重点与两个直接竞品作者探索共享 fixture、互相导入报告或合并治理。如果对方已经愿意完整承载本计划且治理开放，参与现有项目可能比重复建仓更有社区价值。若继续独立实现，禁止复制无明确许可证的代码或测试资产，采用有 provenance 的 independent reimplementation；只有法律顾问要求人员隔离时才使用严格法律意义的 clean-room 流程。

### 0.5 推荐技术决策

| 决策 | 选择 | 原因 |
|---|---|---|
| 核心语言 | Go | 单文件分发、HTTP/SSE/并发成熟、跨平台、用户已有 Go 背景 |
| SDK Runner | Python + Node.js 子进程/OCI | 必须运行真实官方 SDK 和 Vercel AI SDK |
| Scenario | YAML + JSON Schema + CEL | 人可读、可 lint、无任意代码执行 |
| 内部事件模型 | capture-layer evidence + provider-neutral IR 双轨 | 支持跨协议关系检查，但不丢失原始差异 |
| 主仓库 | Polyglot monorepo | engine、packs、profiles、schema 与 release 能原子演进 |
| License | Apache-2.0 | 宽松、企业友好、明确专利授权 |
| 公共数据 | 按 DATA_LICENSE 分类；仅权利清楚、明确授权的事实导出可 CC0-1.0 | 不把第三方输出、身份或 trace 自动改许可 |
| 贡献签署 | DCO 1.1 | 比 CLA 摩擦更小 |
| Engine 版本 | SemVer | 稳定 CLI/config/result/plugin contract |
| Protocol Pack | CalVer + 不可变 digest | 绑定规范快照和观察时间 |
| Registry 证明 | in-toto predicate + Sigstore | 绑定二进制、pack、profile、runner 和结果 |

### 0.6 资源量级

成熟 v1.0 不是 4–6 周项目。粗略工作量：

| 工作流 | 人月 |
|---|---:|
| 规范库、Scenario DSL、协议治理 | 2–3 |
| Engine、Planner、Recorder、Oracle | 4–5 |
| OpenAI Chat/Responses/Anthropic packs | 5–7 |
| SDK Runner 与真实 Agent profiles | 4–5 |
| Reproducer、报告、CI 集成 | 2–3 |
| Registry、签名、Web Matrix | 3–4 |
| 安全、供应链、文档、治理 | 3–4 |
| 合计 | 23–31 人月 |

23–31 人月是未计 Codex 增益的工程量级。假设 Codex 对 fixture、driver、测试和文档等可重复工作带来约 25–35% 净效率提升，但不能压缩外部 review、安全采购、采用和 RC 时间：单人配合 Codex 预计 16–22 个自然月；2–3 名稳定工程师 10–14 个月；4–5 名工程师 8–12 个月，置信区间约 ±30%。估算包含一次外部安全评审/渗透、法律/数据条款、跨平台发布和 6 周 RC，不包含等待第三方修复的不可控时间与云成本。

GA 后 hosted Registry 预计需要合计 0.75–1.5 FTE 覆盖运维、安全、滥用、争议、数据请求和 source drift；若实际容量不足，按第 27 节阻断/缩 scope，不能假设 0.5 人长期足够。

### 0.7 如何阅读和执行本文

| 目的 | 先读章节 |
|---|---|
| 判断是否值得独立建仓 | 0、1、24.3、27 |
| 实现核心 Engine | 7–14、25 |
| 实现协议与真实客户端 | 15–18 |
| 建成熟公共开源项目 | 19–23、28 |
| 让 Codex Goal Mode 开工 | 29、31、34 |
| 判断能否发布 v1.0 | 30 |

文中信息分四类：

- 外部事实：尽量紧邻一手来源链接，并受 2026-07-10 调研基线约束；
- 项目设计决定：是本项目要实现的 contract，变更需 ADR/RFC；
- 量化目标：是内部收敛 gate，不代表行业标准或第三方保证；
- 示例 schema/命令：用于锁定语义，P01 后以仓库生成的正式 schema 和 CLI reference 为准；省略号不是可直接提交的数据。

大写 MUST/SHOULD/MAY 仅用于外部规范 requirement level；中文“必须/应当”表示本项目设计或交付 gate。P00/P01 尚未批准的设计决定保持 provisional，不能冒充外部事实。

实现期间若外部事实变化，按第 33 节更新 source/pack，不静默改写历史结果。

---

## 1. 项目章程

### 1.1 愿景

让任何模型服务、推理 Runtime、Gateway 或 Agent 平台都能用可复现证据回答：

> 这个具体版本和配置，对哪些协议、SDK 和 Agent 客户端真实可用？哪里不兼容？怎样最小复现和修复？

### 1.2 North Star Metric

> 每月由 AgentAPI Doctor 发现、最小化，并被上游确认或修复的独立兼容问题数量。

Star、下载量和 follower 是传播指标，不是唯一成功标准。

### 1.3 目标

- 建立独立、可版本化、可追溯到官方来源的协议测试库。
- 将 wire conformance、model capability、client compatibility 和 reliability 分离。
- 覆盖真实 Agent 所依赖的 streaming、tools、reasoning、state 和 structured output。
- 对失败生成脱敏 capture-layer evidence、client-observed 结果、规范依据和最小 reproducer。
- 让 vLLM、llama.cpp、Ollama、SGLang、LiteLLM 等上游能在 PR/nightly/release CI 使用。
- 建立带签名、可复跑、可申诉、不会被修改历史的公共兼容观察矩阵。
- 形成公开的 Agent API failure corpus，为工程改进和研究提供数据。

### 1.4 非目标

- 完整证明某实现符合全部未公开协议行为。
- 用一次运行证明 endpoint 永久兼容。
- 评价模型知识、事实性、代码能力或通用智能。
- 保证安全、隐私、可用性、成本或业务正确性。
- 覆盖所有 Provider 私有 extension 和全部 hosted tools。
- 读取或评价隐藏 Chain-of-Thought；仅验证公开 summary 和 opaque artifact 的传递。
- 默认进行大并发压测、长上下文成本测试或付费 built-in tool 测试。
- 首个稳定版覆盖 Assistants、Fine-tuning、Batch、图像/视频生成、Realtime WebRTC。

### 1.5 设计原则

1. **Evidence over score**：证据、版本和复现优先于分数。
2. **Client-observed**：同时记录明确 capture layer 的应用层证据和客户端实际观察。
3. **No silent coercion**：方言适配不能掩盖严格协议失败。
4. **Immutable semantics**：发布后的 pack、profile 和 result 不静默改义。
5. **Safe by default**：无遥测、无上传、无真实副作用、强脱敏、硬预算。
6. **Spec-linked**：每个 normative assertion 都有官方来源和快照。
7. **Statistically honest**：模型随机性用重复实验和置信区间，不伪装成确定性。
8. **Upstream first**：发现问题后优先贡献 fixture、Issue 或修复给上游。
9. **Extensible without arbitrary code**：声明式 pack 默认安全，可执行 driver 隔离。
10. **Independent governance**：厂商、Sponsor 不能购买结论或单独批准自己的结果。

---

## 2. 用户与核心使用场景

### 2.1 推理 Runtime / Gateway 维护者

典型对象：vLLM、SGLang、llama.cpp、Ollama、LM Studio、LiteLLM、OpenRouter 类服务。

核心任务：

- PR 中运行确定性 wire pack。
- nightly 使用真实模型运行 behavior 与 Agent profile。
- release 前比较旧版与新版的兼容 diff。
- 将用户日志转成稳定 fixture 和回归测试。
- 自动生成能提交给 SDK/Client 的最小复现。

### 2.2 SDK / Agent 客户端维护者

典型对象：OpenAI Python/Node、Vercel AI SDK、Codex、OpenClaw、Claude Code。

核心任务：

- 对合法、边界、未知扩展和畸形 fixture 做 parser regression。
- 判断用户问题来自 endpoint 还是 client。
- 在 Issue 模板中要求附加 doctor report。
- 发布精确版本绑定的受支持 endpoint/profile 声明。

### 2.3 模型 API 提供商

核心任务：

- 将“OpenAI compatible”营销语转化为明确 feature/profile 声明。
- 协议或 SDK 更新后检测 drift。
- 提交签名 self-report，完成 ownership verification 后申请独立重测。
- 在文档中展示带日期、pack 和证据链接的 badge。

### 2.4 企业 Agent 平台

核心任务：

- 新 Provider 上线准入。
- 模型、Gateway、Chat Template 或 Tool Parser 升级回归。
- 私有环境中运行，不上传 endpoint、key、prompt 或模型名。
- 输出 JUnit/JSON 接入内部 CI 和发布门禁。
- 自托管 Registry 管理企业兼容基线。

### 2.5 本地模型用户

核心问题：

> 这个 Ollama/vLLM/llama.cpp + Qwen/DeepSeek/GLM 组合能否跑 Codex 或 OpenClaw？

用户应在一条命令后得到：

- 可运行/不可运行/部分可运行。
- 失败发生在哪个层次。
- 已知 workaround。
- 可复制的最小复现。

---

## 3. 被测系统模型与故障域

一个结果不能只绑定“模型名称”。实际链路是：

~~~text
Client / Agent
  → SDK / Client parser
  → Gateway / Translator
  → API frontend / serializer
  → Inference runtime
  → chat template / tokenizer
  → reasoning parser / tool parser
  → model weights + decoding config
  → reverse path
~~~

报告必须尽量记录：

- Client/SDK 名称和精确版本。
- Gateway、Runtime 版本、commit、容器 digest。
- 请求模型 ID 与响应模型 ID。
- 模型 revision、量化方式。
- Tokenizer 和 chat template hash。
- Tool parser、reasoning parser、structured-output backend。
- 并行工具、strict schema 等启动参数。
- OS、architecture、区域、时间。

缺失元数据必须显示为 unknown，不能猜测。

### 3.1 故障域枚举

~~~text
TRANSPORT
AUTH
REQUEST_MAPPING
PROTOCOL_SERIALIZER
STREAM_STATE_MACHINE
TOOL_PARSER
REASONING_PARSER
CHAT_TEMPLATE
MODEL_BEHAVIOR
SDK_PARSER
AGENT_ORCHESTRATION
GATEWAY_TRANSLATION
RATE_LIMIT_OR_TRANSIENT
HARNESS
SPEC_AMBIGUITY
UNKNOWN_FAULT_DOMAIN
~~~

归因必须给证据和 confidence；除非差分实验已经确认，不使用武断结论。

`fault_domain` 使用上面的细粒度枚举；`fault_family` 是稳定的公共聚合轴。两者通过 versioned taxonomy 一一映射，`wire` 不是随意插入的同义词：

| fault_family | fault_domain |
|---|---|
| transport | TRANSPORT、AUTH、RATE_LIMIT_OR_TRANSIENT |
| wire | REQUEST_MAPPING、PROTOCOL_SERIALIZER、STREAM_STATE_MACHINE、GATEWAY_TRANSLATION |
| protocol | TOOL_PARSER、REASONING_PARSER |
| model | CHAT_TEMPLATE、MODEL_BEHAVIOR |
| client | SDK_PARSER、AGENT_ORCHESTRATION |
| harness | HARNESS |
| unknown | SPEC_AMBIGUITY、UNKNOWN_FAULT_DOMAIN |

Finding 必须同时保存 `fault_domain` 与派生的 `fault_family`；evaluator 重新计算并拒绝不匹配组合。Transport 表示连接/认证/瞬态服务边界，wire 表示请求/响应映射、序列化和事件状态，protocol 表示结构已到达但工具/推理语义解析失败。Operational Reliability 仍是第 4 节的结果维度，不另造一个含糊故障域。

### 3.2 归因实验

- 同 endpoint：raw HTTP 与多个 SDK 对比。
- 同语义：stream 与 non-stream 对比。
- 同模型：不同 runtime/tool parser 对比。
- 同 runtime：不同模型/chat template 对比。
- 同 endpoint：直连与经过 Gateway 对比。
- 同 fixture：不同 client version 对比。
- 同工具流程：Chat、Responses、Anthropic Messages 对比。

输出示例：

~~~text
Protocol serializer   CONFIRMED
Evidence: missing output_index in three required events

Vercel AI SDK         DOWNSTREAM_VICTIM
Evidence: reference fixture passes; live wire is rejected by Zod

Model behavior        UNLIKELY
Evidence: non-stream response contains a valid tool call
~~~

---

## 4. 兼容性判定模型

### 4.1 五个独立维度

| 维度 | 主要 Oracle | 随机性 | 典型输出 |
|---|---|---:|---|
| Transport | HTTP/SSE/WS 状态机 | 低 | PASS/FAIL |
| Protocol | Schema、关系约束、规范 | 低 | PASS/FAIL |
| Model Behavior | 任务与参数断言 | 高 | 成功率 + 置信区间 |
| Client Compatibility | 真实 SDK/Agent | 中 | COMPATIBLE/DEGRADED/INCOMPATIBLE |
| Operational Reliability | 重复运行与错误统计 | 中高 | flakiness、分位数 |

禁止生成一个模糊的 Overall Score 作为主要结论。

表中的 DEGRADED 只用于一组 case 的 Profile 聚合结论，不是单个 Case Verdict。

### 4.2 Capability 状态

~~~text
SUPPORTED
UNSUPPORTED
PARTIAL
UNKNOWN
~~~

证据来源：

~~~text
DECLARED
DISCOVERED
PROBED
INFERRED
~~~

“模型列表中存在”不代表支持 tools、vision 或 structured output。Capability 声明是测试计划输入，不是通过证据。

### 4.3 Case Verdict

以下枚举分别属于不同字段，禁止互换。

PlanDisposition；由 ResolvedRunPlan 在执行前确定：

~~~text
execute
skip
not_applicable
~~~

ExecutionStatus：

~~~text
planned
running
completed
skipped
cancelled
errored
~~~

Verdict；只有 completed 的 assertion/case 才有：

~~~text
PASS
FAIL
WARN
INCONCLUSIVE
~~~

文档与终端使用大写标签；stable JSON/SARIF/Registry schema 统一序列化为小写 snake_case，例如 verdict=inconclusive、reason_code=transient_error，避免同一 public schema 混用大小写。

ReasonCode 解释执行或判定原因，不是 Verdict。首个稳定集合：

~~~text
unsupported_capability
transient_error
spec_ambiguity
budget_exhausted
cost_limit
unsafe_operation
harness_error
driver_error
cancelled_by_user
flaky_detected
insufficient_samples
not_observed
~~~

ProfileOutcome：

~~~text
COMPATIBLE
DEGRADED
INCOMPATIBLE
INCONCLUSIVE
~~~

规则：

- MUST assertion 失败会阻断相应 conformance/profile。
- SHOULD 失败默认 WARN。
- 明确拒绝未声明的可选功能更新 CapabilityStatus=unsupported；ResolvedScenario 使用 plan_disposition=not_applicable、reason_code=unsupported_capability，不创建 target Verdict。
- 声称支持但静默忽略参数或返回非法结果是 FAIL。
- 429、网络抖动、上游 5xx 默认是 INCONCLUSIVE，reason_code=transient_error。
- 规范冲突是 INCONCLUSIVE，reason_code=spec_ambiguity。
- Harness/Driver 错误使用 execution_status=errored 和对应 reason_code，不产生 endpoint Verdict。
- cost、unsafe、budget 引起的未运行使用 execution_status=skipped 和对应 reason_code。
- FLAKY 是多个 attempt 的 Operational Reliability 统计/标签，不是单次 Verdict；每个 attempt 仍保留自身结果。

### 4.4 状态命名空间与生命周期

| Namespace | 字段 | 枚举 | 用途 |
|---|---|---|---|
| Planning | plan_disposition | execute/skip/not_applicable | scenario 是否适用/被计划执行 |
| Run/Attempt execution | execution_status | planned/running/completed/skipped/cancelled/errored | 是否实际执行与怎样终止 |
| Assertion/Case judgment | verdict | pass/fail/warn/inconclusive | 对已执行观察证据的判断 |
| Capability | capability_status | supported/unsupported/partial/unknown | 目标声称/观测到的能力 |
| Profile aggregate | profile_outcome | compatible/degraded/incompatible/inconclusive | 一组 gates 的客户端结论 |
| Registry dimension | dimension_outcome | pass/fail/degraded/inconclusive/not_run | 五维公共聚合 |
| Goal execution | phase_status/work_unit_status | 第 29.2 节定义 | Codex 实施进度 |

不允许从 reason_code 直接推断 CapabilityStatus 或 ProfileOutcome；聚合规则由 versioned profile gate 定义。例如一个 transient_error 使该次 case inconclusive，不自动证明 endpoint unsupported。

Disposition/Result truth table：

| plan_disposition | Attempt | execution_status | verdict | 分母 |
|---|---|---|---|---|
| execute | 创建 | completed | pass/fail/warn/inconclusive | candidate、applicable、executed 都计 |
| execute | 创建 | errored/cancelled | 无 | candidate/applicable 计，executed-success 不计；required gate 不能 compatible |
| skip | 不创建 target Attempt | skipped summary | 无 | candidate/applicable 计，executed 不计；必须显示 cost/unsafe/budget reason |
| not_applicable | 不创建 | 无或 skipped summary | 无 | candidate 计，applicable/executed 不计；必须有 capability/condition evidence |

报告同时显示 candidate、applicable、executed 三个 denominator digest/count。not_applicable 只能由冻结 resolver 条件产生；用户为提高比例而关闭能力只能是 skip。Tier 1 required scenario 被 skip/errored/cancelled 时不能得到 compatible。

### 4.5 Model Behavior 统计

- 快速诊断：5 次。
- 标准报告：20 次。
- 发布级研究：50 次以上。
- 默认使用 Wilson 置信区间。
- 记录 seed、temperature、top_p、模型 revision 和完整服务配置。
- 即使支持 seed，也不承诺完全确定。
- Failure minimizer 只有在缩减后仍达到预设复现概率时才接受结果。

### 4.6 Profile 结论

结果必须带版本：

~~~text
Observed compatible
Client: Codex CLI 0.144.1
Protocol: OpenAI Responses HTTP/SSE
Pack: openai-responses-http@2026.07.0
Runtime: vLLM <exact-version>
Model/config: <digest>
Observed at: <UTC timestamp>
~~~

Badge 必须同时显示 profile、pack 和 freshness；禁止无版本的永久 “Agent Compatible”。

---

## 5. 四个测试平面

### 5.1 Plane A：Endpoint Black-box

直接向目标 endpoint 发请求，记录真实 wire。

适合：

- 请求/响应 Schema。
- SSE 状态机。
- 错误、usage、取消。
- forced tool choice。
- stream/non-stream metamorphic comparison。

限制：

- 无法保证模型触发某个随机路径。
- 很难精确区分模型、template、parser 和 serializer。
- 未触发路径只能 INCONCLUSIVE，不能判 PASS。

### 5.2 Plane B：Controlled Backend / Provider CI

让 Gateway 或 Runtime 连接项目提供的脚本化上游，或通过 runtime adapter 注入受控模型输出/token stream。

适合：

- 确定性触发并行 tool calls、畸形 tool JSON、reasoning/tool 交错。
- 验证 Gateway 转换。
- 验证 Runtime parser/serializer。
- release gate。

通用 engine 只定义 Controlled Backend Contract；各 Runtime 通过 adapter 实现。无法受控注入的 Runtime 不宣称完整 deterministic conformance。

### 5.3 Plane C：Client Fixture Replay

项目提供确定性 reference/mutant endpoint，让真实 SDK/Agent client 消费固定 wire fixture。

适合：

- SDK parser。
- 未知字段/事件前向兼容。
- 任意 SSE rechunk。
- 断流、重复、乱序、空 delta。
- 不需要真实付费模型。

### 5.4 Plane D：Real Agent End-to-End

真实 Codex/OpenClaw/Vercel AI SDK 等连接真实 endpoint，在隔离环境完成小型工具任务。

必须使用：

- 临时 HOME 和临时 Git repo。
- 合成文件、合成工具和 canary。
- 默认无外网。
- 无真实账户、支付、邮件、数据库等副作用。
- 明确请求/token/时间预算。

该平面验证“能否工作”，不能证明完整协议合规。

---

## 6. 协议与客户端支持层级

### 6.1 稳定 v1.0 核心

| 类型 | Pack/Profile | 状态 |
|---|---|---|
| Protocol | OpenAI Chat Completions HTTP/SSE | Tier 1 |
| Protocol | OpenAI Responses HTTP/SSE | Tier 1 |
| Protocol | Anthropic Messages HTTP/SSE | Tier 1 |
| SDK | OpenAI Python latest + previous | Tier 1 |
| SDK | OpenAI Node latest + previous | Tier 1 |
| SDK | Anthropic Python/Node latest + previous | Tier 1 |
| Client | Codex latest + previous | Tier 1 |
| Client | OpenClaw latest + previous | Tier 1 |
| Client | Vercel AI SDK latest + previous | Tier 1 |
| Runtime | vLLM、llama.cpp、Ollama、SGLang、LiteLLM metadata adapters | Tier 1 |

latest + previous 是 release policy，不是浮动的 ResolvedRunPlan 输入。每次 release 从 support-manifest.yaml 解析并生成 support-lock.yaml，固定 package/client version、runtime/toolchain 和 artifact digest；后续上游发布不会改变既有结果。

### 6.2 v1.0 Required Tier 2 Extensions

当前 release-components.yaml 要求以下能力随项目 v1.0 交付，但只以 Experimental/Tier 2 标签发布，不计入 Tier 1 核心 conformance：

- Open Responses upstream compliance suite adapter。
- Google generateContent。
- Google Interactions。
- MCP lifecycle/tools/stdio/Streamable HTTP 的声明 scope。
- Ollama native ProtocolPack 与对应 OpenClaw Tier 2 profile。

P06 必须让它们达到第 6.5 节 Tier 2 gate；未实现会阻断当前整体 v1.0 release，但不会被包装成 stable compatibility。只有未来达到 Tier 1 全部门禁，才可在 v1.x 晋级。

#### 6.2.1 v1.x Optional Promotion Candidates

以下不在当前 v1.0 release-components required set，按真实 adopter 需求进入后续版本：

- OpenAI Responses WebSocket。
- Google GenAI Python/Node SDK。
- Claude Code Anthropic-format Gateway profile。
- LangGraph/OpenAI Agents SDK profile。
- Azure OpenAI、Bedrock、Vertex 认证与 URL profiles。
- Provider-hosted remote MCP connector profiles。

### 6.3 独立 Extension Packs

- MCP advanced OAuth/tasks/provider connector 深化（超出 6.2 声明 scope）。
- Embeddings。
- Files。
- Batch。
- Realtime Audio/WebRTC。
- Image/Video generation。
- Hosted tools。
- Long-context、performance、rate-limit stress。

OpenAI Assistants API 将在 2026-08-26 sunset，项目不投入完整 pack，只提供迁移提示：[OpenAI deprecations](https://developers.openai.com/api/docs/deprecations)。

### 6.4 Pack 与 Profile 分离

~~~text
packs/
  openai-chat/
  openai-responses-http/
  anthropic-messages/
  extensions/
    openai-responses-websocket/
    google-generate-content/
    google-interactions/
    mcp-2025-11-25/
    ollama-native/

profiles/
  sdk/
    openai-python/
    openai-node/
    anthropic-python/
    anthropic-node/
  clients/
    vercel-ai-sdk/
    codex/
    openclaw/
    claude-code/
  providers/
    generic-openai/
    azure-openai/
    ollama-native/
    vertex-gemini/
    bedrock/

adapters/
  external-suites/
    open-responses/
  dialects/
  runtime-metadata/
    vllm/
    sglang/
    llama-cpp/
    ollama/
    litellm/
~~~

这是第 8 节 monorepo 的规范子树，不是另一套扁平布局。ProtocolPack 只在 `packs/`，Consumer/Provider profiles 只在 `profiles/<kind>/`，ExternalSuiteAdapter、DialectAdapter、RuntimeMetadataAdapter 只在 `adapters/<kind>/`。P01 后 `artifacts/identity-grammar.yaml` 和 impact-map 校验 artifact kind 与路径；同一 artifact 不得在两个目录各存一份。

ProviderConnectionProfile 只描述 URL、认证和 metadata 获取；DialectAdapter 单独描述已知转换。二者都不能修改 normative pack 的真值。若用户启用 lenient dialect，报告必须同时展示 strict 结果和 adapted 结果。

### 6.5 Tier 的可计算定义

| 条件 | Tier 1 Stable | Tier 2 Experimental | Tier 3 Incubating |
|---|---|---|---|
| Requirement | 所有 applicable MUST 有一手来源并通过；SHOULD 公开 | 选定 scope 的 MUST 有来源，known gaps 完整 | 可只有 proposal/source mapping |
| Assertion quality | 每个 normative assertion 有 reference pass + targeted mutant fail | 核心 assertion 有 reference/mutant | Schema/lint 至少通过 |
| Taxonomy | 声明 scope 全覆盖 | 明确子集 | 不承诺覆盖 |
| Client/version | support lock 中 latest + previous 两个精确版本全过 | 至少一个精确版本 | 社区自报 |
| CI | PR deterministic + nightly matrix + release blocker | nightly/best effort，不阻断 core release | 无持续保证 |
| Ownership | 主 owner + backup owner | 至少一名 owner | contributor 自愿 |
| Known gaps | required 路径无 unresolved spec ambiguity/P0/P1 | 允许公开 gaps/inconclusive | 不完整 |
| Public label | 可发带 pack/profile/digest/freshness 的 stable observation | 只能发 Experimental observation | 不发 compatibility badge |

Tier 1 的“全部 applicable MUST”分母由不可变 Requirement Catalog/denominator digest 定义；重复、alias 或只改名 scenario 不增加 coverage。required 路径出现 verdict=inconclusive、reason_code=spec_ambiguity 时不能发布 compatible outcome。

Tier 是具体 artifact/cell 的属性，不是把表中每一行机械套给所有对象。Gate 必须先按 artifact kind 选择 applicability rule；任何 `not_applicable` 都要保存 rule ID 和证据，不能用它绕过缺失实现：

| Artifact/cell | 必须适用的门禁 | `Client/version` 行 |
|---|---|---|
| ProtocolPack | Requirement、Assertion quality、Taxonomy、CI、Ownership、Known gaps、Public label | N/A；用固定 reference/mutant 与 protocol revision 证明 Pack，本身不要求某个消费端 |
| ConsumerCompatibilityProfile + Driver cell | 该 profile 的 de-facto/consumer requirements、reference/mutant 或 controlled-backend gates、CI、Ownership、Known gaps、Public label | 必须适用；Tier 1 为 support lock 中 previous/current，Tier 2 至少一个 exact consumer |
| ExternalSuiteAdapter | 固定 upstream version/digest、结果保真映射、adapter mutants、CI、Ownership、Known gaps、Public label | 默认 N/A；只有它同时声明 consumer profile 时才适用 |
| ProviderConnectionProfile / RuntimeMetadataAdapter | 自身 contract、配置/采集 fixtures、CI、Ownership、Known gaps；不得获得 Protocol conformance label | 仅在实际执行某个 consumer 时适用，否则 N/A |
| 组合 release matrix cell | 所引用的 Pack、Profile、Driver、Consumer 各自 gate 全部通过 | 按 cell 声明适用，缺一不能宣称 client-compatible |

因此 P03 可以让三个 ProtocolPack 达到 Tier 1 artifact gate；只有 P04 完成精确 SDK/Agent support matrix 后，对应的组合 client cells 才能发布 Tier 1 compatible observation。P06 中 Google/MCP ProtocolPacks 的 client/version 为 N/A，Open Responses ExternalSuiteAdapter 固定 upstream suite/adapter identity；Ollama native + OpenClaw profile 则必须通过至少一个 exact OpenClaw consumer 的 Tier 2 gate。未来加入 Google SDK profile 时才激活它自己的 consumer/version gate。

support-manifest.yaml 是支持政策/逻辑 matrix 的唯一机器可读来源。每个 cell 包含 artifact kind/name、Tier、version selector、required OS/arch、CI cadence、releaseBlocking、owner+backup、update SLA、known-gap policy 和对应 D30 IDs；每次 release 解析成 support-lock.yaml，加入 profile/driver/consumer exact version/digest 与 pack/denominator digest。§6.1、E06、P04、release notes 和 Web Matrix 由二者生成，防止“文档承诺 7 个、gate 只测 6 个”。

OpenAI Responses 是 OpenAI 的 provider API；Open Responses 是独立的开放规范/项目，二者名称相近但不是同一 contract。v1.0 只把 Open Responses 官方 compliance suite 作为 Tier 2 external-suite adapter，保留其原始结果和许可证，不用它替代 OpenAI Responses Tier 1 pack。

---

## 7. 总体架构

~~~mermaid
flowchart TD
    S["Spec sources"] --> P["Pack compiler"]
    C["Config and profiles"] --> L["Planner"]
    P --> L
    L --> D["Drivers and runners"]
    D --> T["Target endpoint / fixture server"]
    T --> W["Wire recorder"]
    W --> N["Normalizer and event IR"]
    W --> O["Raw-wire oracles"]
    N --> O
    O --> A["Attribution and minimizer"]
    A --> R["Report bundle"]
    R --> J["Local CI outputs"]
    R --> G["Signed registry observation"]
~~~

### 7.1 组件职责

1. **Spec Catalog**
   - 记录官方来源、commit/revision、hash、稳定性、许可证和歧义。
   - 生成变更 diff，但不自动改变结论。

2. **Pack Compiler**
   - 校验 YAML/JSON Schema。
   - 编译 CEL assertion。
   - 解析依赖、capability 和预算。
   - 生成不可变 pack digest。

3. **Planner**
   - 合并 config、target、pack、profile。
   - 做 preflight 和 capability discovery。
   - 生成可审阅的 IntentPlan 与 ResolvedRunPlan。
   - 计算请求/token/时间上限。

4. **Driver Runtime**
   - raw HTTP driver。
   - SDK subprocess/OCI runner。
   - Agent client runner。
   - Controlled backend adapter。

5. **Wire Recorder**
   - 记录脱敏 request/response、SSE event、时间、终止和连接信息。
   - 同时支持 SDK 通过本地 recording forward proxy 访问目标。

6. **Normalizer**
   - 构建内部 typed event IR。
   - 保留 provider extension 和 capture-layer evidence pointer。
   - 绝不以 IR 替代原始证据。

7. **Oracle**
   - Schema、state machine、relational、metamorphic、behavioral assertions。

8. **Attribution Engine**
   - 根据差分实验和因果证据定位故障域。
   - 输出 confidence 和 unresolved alternatives。

9. **Failure Minimizer**
   - 缩减 request、tools、schema、turn、fixture event 和 chunk pattern。
   - 生成 curl/Python/Node/Agent repro。

10. **Report/Registry**
    - 本地多格式报告。
    - 签名 observation、信任等级、freshness、supersede 和 dispute。

---

## 8. Monorepo 结构

~~~text
agentapi-doctor/
├── cmd/
│   ├── doctor/                  # 主 CLI
│   └── registry/                # 独立部署的 Registry 服务
├── internal/
│   ├── config/
│   ├── planner/
│   ├── transport/
│   ├── recorder/
│   ├── redaction/
│   ├── normalizer/
│   ├── oracle/
│   ├── statemachine/
│   ├── statistics/
│   ├── attribution/
│   ├── minimizer/
│   ├── report/
│   ├── budget/
│   ├── provenance/
│   └── registry/
├── pkg/
│   ├── schema/                  # 稳定 public Go API
│   ├── driverprotocol/          # out-of-process driver contract
│   └── packapi/
├── schemas/
│   ├── index.yaml
│   ├── migration-floor.yaml
│   ├── scenario/
│   ├── pack/
│   ├── profile/
│   ├── result/
│   └── attestation/
├── cli/
│   └── spec.yaml
├── artifacts/
│   └── identity-grammar.yaml
├── specs/
│   ├── catalog/
│   └── ambiguities/
├── packs/
│   ├── openai-chat/
│   ├── openai-responses-http/
│   ├── anthropic-messages/
│   └── extensions/
│       ├── openai-responses-websocket/
│       ├── google-generate-content/
│       ├── google-interactions/
│       ├── mcp-2025-11-25/
│       └── ollama-native/
├── profiles/
│   ├── sdk/
│   ├── clients/
│   └── providers/
├── adapters/
│   ├── external-suites/
│   │   └── open-responses/
│   ├── dialects/
│   └── runtime-metadata/
├── runners/
│   ├── python/
│   ├── node/
│   └── images/
├── fixtures/
│   ├── canonical/
│   ├── boundary/
│   ├── negative/
│   ├── regression/
│   ├── mutation/
│   └── client/
├── reference/
│   ├── server/
│   ├── mutant-server/
│   └── synthetic-tools/
├── registry/
│   ├── api/
│   ├── migrations/
│   └── moderation/
├── web/
│   ├── matrix/
│   └── docs/
├── integrations/
│   ├── github-action/
│   ├── reusable-workflow/
│   ├── homebrew/
│   └── scoop/
├── docs/
│   ├── concepts/
│   ├── guides/
│   ├── protocol-packs/
│   ├── client-profiles/
│   ├── threat-model/
│   └── reference/
├── rfcs/
├── adrs/
├── execution/
│   ├── ga-criteria.yaml
│   ├── phase-state.yaml
│   ├── product-stage-map.yaml
│   ├── impact-map.yaml
│   └── ...
├── support/
│   ├── support-manifest.yaml
│   ├── support-lock.yaml
│   └── release-components.yaml
├── sources.lock.yaml
├── corpus/
│   └── upstream-issues/
├── test/
│   ├── e2e/
│   ├── conformance/
│   ├── fuzz/
│   └── upgrade/
├── .github/
├── README.md
├── AGENTS.md
├── GOVERNANCE.md
├── SECURITY.md
├── CONTRIBUTING.md
├── SUPPORT.md
├── RELEASE.md
├── DATA_POLICY.md
├── DATA_LICENSE.md
├── REGISTRY_TERMS.md
├── PRIVACY.md
├── ACCEPTABLE_USE.md
├── TRADEMARKS.md
├── ROADMAP.md
├── MAINTAINERS.md
├── CODE_OF_CONDUCT.md
├── ADOPTERS.md
├── Makefile
├── LICENSE
└── NOTICE
~~~

### 8.1 稳定 API 边界

v1.0 前必须明确以下 public contract：

- CLI 命令、flags、exit codes。
- Config schema。
- Scenario/Pack/Profile schema。
- Result bundle schema。
- Driver subprocess protocol。
- Go 包中明确标记 stable 的类型。
- Registry ingestion API。

internal 目录不承诺兼容。Plugin 不以内嵌 Go shared object 实现，避免 ABI、崩溃和任意代码风险。

---

## 9. 规范来源、Requirement Catalog 与版本治理

### 9.1 来源优先级

当官方材料冲突时，按以下顺序判断，但保留人工裁决：

1. 带明确 MUST/SHOULD 语义的稳定协议。
2. 官方发布且版本固定的 OpenAPI/Schema。
3. 官方 API Reference。
4. 官方 SDK 类型和官方 SDK 测试。
5. 官方 Guide 和示例。
6. 官方服务实测行为。
7. 社区广泛依赖的 de-facto 行为。

官方 SDK 和官方服务也可能有 Bug，不能用“官方 SDK 接受了”代替协议证据。无法裁决时返回 SPEC_AMBIGUITY，不把争议解释强加为 Provider FAIL。

OpenAI 的 OpenAPI 规范仓库可作为重要输入：[openai/openai-openapi](https://github.com/openai/openai-openapi)。Responses streaming 还必须结合官方 typed event 文档，因为仅靠普通 REST Schema 很难表达完整事件时序：[OpenAI Streaming Responses](https://developers.openai.com/api/docs/guides/streaming-responses)。

### 9.2 Requirement Catalog

每一个 normative assertion 必须先进入独立 Requirement Catalog：

~~~yaml
apiVersion: urn:agentapi-doctor:requirement:v1
kind: Requirement

metadata:
  id: OAI-RESP-STREAM-FUNC-004
  title: Function argument deltas reconstruct one JSON string

spec:
  protocol: openai-responses
  protocolSnapshot: "2026-07-10"
  level: MUST
  category: normative
  automatable: true

  source:
    uri: https://developers.openai.com/api/reference/resources/responses/streaming-events
    locator: response.function_call_arguments.delta
    retrievedAt: "2026-07-10T00:00:00Z"
    snapshotDigest: sha256:...
    licenseStatus: reference-only

  interpretation:
    statement: >
      Argument deltas are string fragments and must reconstruct the final
      function-call arguments associated with the same item/call.
    ambiguity: none

  scenarios:
    - openai.responses.stream.function-arguments

  ownership:
    team: protocol-openai
~~~

分类必须为下列之一：

- normative：有明确稳定规范依据。
- de-facto-client：具体 SDK/Client 的实际要求。
- consumer-profile：某 Agent 的集成要求。
- behavioral：模型行为能力。
- advisory：性能、可观测性或最佳实践。

禁止把 de-facto SDK 行为倒推成协议 MUST。

### 9.3 Spec Lock

每个 Protocol Pack 保存不可变来源清单：

~~~yaml
protocol: openai-responses
packVersion: 2026.07.0
stability: stable

sources:
  - type: openapi
    uri: https://github.com/openai/openai-openapi
    revision: <commit-sha>
    digest: sha256:...
    retrievedAt: 2026-07-10

  - type: documentation
    uri: https://developers.openai.com/api/docs/guides/streaming-responses
    digest: sha256:...
    retrievedAt: 2026-07-10

knownAmbiguities:
  - id: OAI-RESP-AMB-001
~~~

无法确认再分发许可证时，不镜像官方文档全文，只保存 URL、locator、日期、hash、自行撰写的解释和原创建 fixture。

### 9.4 不可变 Pack 与版本轴

| 对象 | 版本策略 |
|---|---|
| Core/CLI | SemVer |
| Scenario DSL | apiVersion |
| Result Schema | 独立 SemVer |
| Driver RPC | 独立 SemVer |
| Protocol Pack | CalVer：YYYY.MM.patch |
| Client Profile | Profile 自身 SemVer；consumerConstraint 是独立字段 |
| Registry API | URL major version |

Identity 必须分开保存，不把多个版本轴塞进一个 SemVer build metadata：

~~~text
packName: openai-responses-http
packVersion: 2026.07.0
protocolRevision: source-snapshot-2026-07-10
artifactDigest: sha256:...

profileName: codex.responses
profileVersion: 1.0.0
consumerConstraint: ">=0.144.1 <0.145.0"
resolvedConsumerVersion: 0.144.1
artifactDigest: sha256:...
~~~

OCI 分发引用使用合法的 repository:tag@digest 形式，例如 oci://<registry>/<namespace>/packs/openai-responses-http:2026.07.0@sha256:...；ResolvedRunPlan 总是保存 digest。latest/previous 只是支持策略选择器，Planner 必须在运行前解析成精确版本和 lock digest。

文档中的 urn:agentapi-doctor:* 是 P00 工作期 provisional namespace，不暗示拥有 agentapi.dev 或任何域名。P00 锁定最终名称/域名后一次性迁移 schema ID、Go module、package、OCI 与 attestation namespace；P01 contract freeze 后不得再变。

发布后的 pack/profile 不得原地修改。Oracle 修正也必须生成新版本，并在 Registry 中标记旧结果 superseded，而不是静默重算历史。

### 9.5 上游变更监测

Nightly Spec Watcher：

- 固定抓取官方 OpenAPI、Schema、SDK types 和公开 reference。
- 计算结构 diff：endpoint、字段、required、enum、event、deprecated。
- 生成 human-readable change report。
- 为新行为生成 Requirement/Scenario skeleton。
- 自动开 PR，但不自动合并或改变 PASS/FAIL。
- 记录 breaking、additive、clarification、docs-only。

重大协议变化必须走 RFC；测试包更新需两名 reviewer，其中至少一名为该 pack maintainer。

---

## 10. Scenario DSL 与 Pack 编译

### 10.1 设计约束

DSL 必须：

- 可读、可 code review、可静态验证。
- 不允许任意 shell/Python/JavaScript。
- 对同一输入生成确定性 canonical IR 和 digest。
- 能表达多步工具循环、stream、cancel、negative 和 statistical tests。
- 每个 assertion 可追溯到 Requirement。
- 明确预算、幂等性、副作用和发布策略。
- 未知字段默认报错，避免拼写被静默忽略。

作者格式使用 YAML；Schema 使用 JSON Schema Draft 2020-12；组合表达式使用受限 CEL。CEL 无 I/O、无网络、无文件访问，并设置 computation cost 上限。

### 10.2 Scenario 示例

~~~yaml
apiVersion: urn:agentapi-doctor:scenario:v1beta1
kind: Scenario

metadata:
  id: openai.responses.streaming.parallel-tool-call
  version: 1.2.0
  title: Two scripted parallel function calls remain valid across streamed deltas
  labels:
    protocol: openai-responses
    feature: tool-calling
    plane: controlled-backend

spec:
  protocol:
    family: openai-responses
    snapshot: "2026-07-10"
    digest: sha256:...

  classification:
    type: normative
    stability: stable
    sideEffects: none
    idempotent: true

  requirements:
    - id: OAI-RESP-STREAM-FUNC-004
      level: MUST

  requires:
    all:
      - streaming
      - function-calling
      - parallel-tool-calls

  budgets:
    timeout: 45s
    maxRequests: 3
    maxInputTokens: 3000
    maxOutputTokens: 1000
    maxArtifactBytes: 16MiB

  steps:
    - id: create
      invoke:
        operation: responses.create
        driver: raw
        controlledBackend:
          fixture: responses/parallel-two-tools-v1
        request:
          model: "{{ target.model }}"
          stream: true
          parallel_tool_calls: true
          tool_choice: required
          tools:
            - fixture: tools/weather.yaml
            - fixture: tools/time.yaml
          input:
            - role: user
              content: Call both tools for Tokyo.

    - id: collect
      capture:
        stream: create.stream
        as: response_stream

    - id: verify
      assert:
        - use: fixture.expected-tool-call-count
          equals: 2
          assertionRole: precondition
          observedAt: controlled-backend-source
        - use: protocol.schema
          assertionRole: normative
        - use: protocol.event-state-machine
          assertionRole: normative
        - use: tool.arguments-concatenate-to-json
          assertionRole: normative
        - use: tool.call-id-unique
          assertionRole: normative
        - use: transform.preserves-tool-call-cardinality
          assertionRole: consumer_profile
          requirement: RUNTIME-CONTROLLED-TRANSFORM-001

  repetition:
    count: 3
    policy: all

  publication:
    dataClass: synthetic-only
~~~

这里的“两次调用”由 Controlled Backend source fixture 保证，是 precondition，不是 OpenAI endpoint 的 normative 要求。parallel_tool_calls=true 允许并行，tool_choice=required 要求工具路径，但都不保证真实模型恰好选择两个工具；Endpoint Black-box 中的调用数量只能归为 behavioral assertion，以重复试验和置信区间报告，不能让 size(tool_calls)==2 导致 Protocol FAIL。[OpenAI Function Calling](https://developers.openai.com/api/docs/guides/function-calling)

assertion_role 固定为 precondition、normative、consumer_profile、behavioral、advisory：

- precondition 只验证 harness/fixture/source 是否建立了可判定路径；
- precondition 失败使 attempt execution_status=errored、reason_code=harness_error，停止后续 target assertions，不进入 endpoint/profile denominator，不产生 target Finding；
- normative 必须引用 protocol Requirement；
- consumer_profile 引用受控转换或具体客户端 Requirement，结果不能倒推为 protocol MUST；
- behavioral 使用重复/统计；
- advisory 不阻断 compatibility。

### 10.3 限定步骤

首个稳定 DSL 只支持：

- invoke
- capture
- register_resource
- provide_tool_result
- wait_for
- assert
- cancel
- replay
- finalize

禁止：

- 任意命令。
- 任意文件读取。
- 动态下载脚本。
- assertion 中发网络请求。
- 引用用户 HOME 或未声明环境变量。

需要真实 Agent CLI 的操作由受控 Driver/Profile 实现，而不是把 shell 塞进 Scenario。

### 10.4 Resource Lease 与 Finalizer

任何 store=true、background、conversation/response ID、remote file 或其他服务端状态都必须声明 ResourceLease：

~~~yaml
resources:
  - id: stored-response
    acquireFrom: create.response_id
    sideEffectClass: reversible-remote
    finalizer:
      operation: responses.delete
      idempotent: true
      retry:
        maxAttempts: 3
    cleanupBudget:
      requests: 3
      duration: 60s

finally:
  - finalize: stored-response
~~~

规则：

- sideEffectClass 只能是 none、reversible-local、reversible-remote、irreversible；stable suite 默认拒绝 irreversible；
- finalizer 在成功、assertion fail、cancel、普通 budget exhaustion 后都按 LIFO 运行；
- cleanup budget 在 run 开始时单独预留，不能被测试步骤消耗；
- 进程崩溃后，journal 中的 lease 由恢复命令/worker 重试；
- finalizer 自身失败不覆盖原 Verdict，单独产生 residual_resource finding 和 execution error；
- report 列出所有 acquired/released/residual resource、最后清理时间和人工 cleanup 命令；
- project-operated runner 有 residual resource 上限，超限立即停止新任务；
- secret/权限撤销后无法清理时进入安全运维队列，不无限重试。

Finalizer 所需的 response/conversation/file locator 可能不能进入普通 Evidence。Core 使用独立 OperationalStateStore：

- 只保存 resource type、最小 locator、target/auth reference、finalizer、expiry 和 run/lease ID；
- 写盘前用该 Run 的独立 AEAD key 加密，key provider/rotation/crypto-erasure 遵循第 20.5 节；
- 不进入 Evidence CAS、report、Result、Observation、备份或公共上传；
- 只有 Core cleanup/recovery identity 可读，Driver/Oracle/Web 不可访问；
- 清理成功立即删除记录和 wrapped key；失败只在报告暴露 residual type/opaque ID，不暴露 locator；
- 无法恢复 key/权限时停止自动重试，产生 residual_resource finding 和人工清理指引；
- self-host/project runner 使用专门加密 operational DB 与审计，retention 不超过 lease expiry + incident window。

### 10.5 编译过程

~~~text
YAML
→ JSON Schema validation
→ semantic validation
→ Requirement/source validation
→ fixture resolution
→ safe variable expansion
→ CEL type/cost check
→ canonical IR
→ RFC 8785 canonical JSON
→ SHA-256 digest
~~~

[RFC 8785](https://www.rfc-editor.org/info/rfc8785/) 提供可用于 hash/signature 的确定性 JSON canonicalization。

### 10.6 Pack Manifest

~~~yaml
apiVersion: urn:agentapi-doctor:pack:v1
kind: ProtocolPack

metadata:
  name: openai-responses-http
  version: 2026.07.0

spec:
  engine:
    minVersion: 1.0.0
    maxMajor: 1

  protocolSnapshot:
    ref: specs/openai-responses/2026-07-10.yaml

  scenarios:
    include:
      - scenarios/**/*.yaml

  conformanceSuites:
    core:
      requirements: [core, streaming, errors]
    agent:
      requirements: [core, streaming, tools, state, structured-output]

  defaultBudget:
    maxRequests: 80
    maxDuration: 15m

  signing:
    digest: sha256:...
~~~

### 10.7 Pack 贡献门槛

新增或修改 normative test 必须：

1. 有 Requirement ID 和一手来源。
2. 在 pack-conforming reference server 上 PASS。
3. 至少能 kill 一个对应 mutant；否则测试可能是 vacuous。
4. 包含 positive、negative 或 boundary fixture。
5. 说明是否会增加请求/token/副作用。
6. 不复制受限日志或大段官方文档。
7. 通过两名 reviewer，其中一名 pack maintainer。

---

## 11. Driver、Protocol Adapter 与 Client Profile

### 11.1 职责分离

**Protocol Adapter**

- 解析 raw request/response。
- 校验 JSON Schema 和事件状态机。
- 构建保留 provider-native 类型/extension 并带 source evidence pointer 的 typed protocol event。
- 构建 normalized view。
- 不负责网络和真实 SDK。

**Driver**

- 使用 raw HTTP、官方 SDK 或真实 Client 发请求。
- 返回 client-observed event、parse error、retry、cancel。
- 精确记录 SDK/runtime 版本。

**Profile**

- 选择 protocol pack、driver、scenario 和 hard gates。
- 表示某个具体消费者版本的真实要求。

### 11.2 Driver RPC

外部 Driver 使用 NDJSON JSON-RPC 2.0 over stdio；首版不同时维护 gRPC 等第二套权威协议。

方法：

~~~text
driver.hello
driver.prepare
driver.capabilities
driver.invoke
driver.cancel
driver.reset
driver.shutdown
~~~

Observation notification：

~~~json
{
  "jsonrpc": "2.0",
  "method": "driver.observation",
  "params": {
    "invocation_id": "inv-01",
    "sequence": 12,
    "kind": "sdk.event",
    "monotonic_ns": 120034500,
    "payload": {}
  }
}
~~~

RPC control plane 与 artifact data plane 分离：

- NDJSON control frame 默认最大 1 MiB；小型 typed observation 可内联；
- invoke 接收 invocation-scoped ephemeral_exact_input_handle，Core 通过受控 pipe/socket/memfd 提供精确 SDK 输入，不默认落盘；real auth 仍由 recorder 注入；
- 大 payload 通过握手协商的单向 length-prefixed companion pipe 分块，单 frame 默认 256 KiB；control message 只引用 invocation/stream/chunk sequence；
- Core 发 flow-control credit 并施加总 bytes/deadline；Driver 必须背压，不能无限 buffer；
- Driver 把 observation bytes 流回 Core，Core 执行 redaction、hash 和 CAS commit 后才产生 payload_ref；
- Driver 没有 CAS 写权限，不能自行声明某 digest 已存在；
- EOF/crash 时未完成 chunk stream 标为 incomplete 并丢弃临时 blob，attempt errored/driver_error，不产生可引用 CAS artifact。

Handshake 包含：

- Driver API version range。
- Driver/SDK 名称与精确版本。
- 协议和 operation。
- stream/cancel/retry 控制能力。
- runtime、OS、arch。
- artifact/lockfile digest。
- 权限声明。

Driver stdout 只允许协议消息，日志写 stderr。违反时 attempt 使用 execution_status=errored、reason_code=harness_error，不产生 target Verdict。

### 11.3 Secret 隔离

默认链路：

~~~text
SDK Driver
  → invocation-scoped localhost/Unix-socket recorder
  → recorder 验证 capability token、ResolvedRunPlan、path 和预算
  → recorder 注入真实 auth
  → ResolvedRunPlan 固定的 target
~~~

这不是一个持有凭据的通用 forward proxy。每次 invocation 由 Core 生成短期随机 capability，绑定 run_plan_digest、invocation_id、child identity、target origin、允许的 method/path/model、redirect policy、请求/字节/时间预算和 expiry。Recorder：

- 只接受对应 sandbox/子进程经 Unix socket 或随机 loopback listener 发来的请求；
- 拒绝任意 absolute URL、CONNECT、自定义 Host、代理链和未在计划内的 operation；
- 每次 redirect 重新执行 target/SSRF policy；
- 在注入 secret 前完成 capability、budget 和 request shape 检查；
- 将 real auth 与 driver 提供的 header 分离，禁止 driver 覆盖；
- capability 一次运行有效，cancel/shutdown 后立即撤销；
- 记录 egress enforcement mode。

Driver sandbox 必须把出网强制经过 recorder；若某平台不能可靠阻断 driver 直连，标记 egress_unenforced，仅允许本地用户显式 opt in，不得在 project-operated runner 使用。

因此受控 Python/Node Driver 默认不接触真实 key。真实 secret 不使用 CLI 参数、不写报告；Core 尽力禁用 core dump、swap/diagnostic dump 并使用最短内存生命周期，但必须记录平台限制，不能无条件宣称“绝不会进入 core dump”。

复杂认证：

- Bearer/custom header：核心注入。
- mTLS：核心 transport。
- SigV4/OAuth refresh：v1 只允许受审、内置 Core auth module；不加载第三方 Auth Provider plugin。
- 必须把 secret 交给 Driver 时，使用匿名 pipe 或权限受限临时文件，并在结果中标记 higher-risk execution。

Auth Provider 比普通 Driver 权限更高。v1 不承诺外部 Auth RPC/plugin；Azure/Bedrock/Vertex profile 只有在对应认证由 Core 内置、完成 threat model 和 contract test 后才能升级支持，否则保持 Tier 2 unsupported。GA 后若需要扩展，先 RFC 定义 capability-scoped RPC、签名分发、secret lifetime、sandbox、audit 和 failure model。

### 11.4 Driver 分发

支持：

1. 内置 Go raw driver。
2. 用户已安装 executable。
3. digest-pinned OCI driver。

不重新分发许可证不允许的客户端二进制。Codex/OpenClaw/Claude Code profile 可调用用户安装的 CLI并验证版本；可开源构建的客户端按其许可证处理。

### 11.5 Profile 示例

~~~yaml
apiVersion: urn:agentapi-doctor:profile:v1beta1
kind: ConsumerCompatibilityProfile

metadata:
  id: codex.responses
  version: 1.0.0

spec:
  consumer:
    name: Codex CLI
    exactVersion: 0.144.1
    source: https://developers.openai.com/codex/

  driver:
    ref: local-executable://codex
    expectedDigest: optional

  required:
    packs:
      - name: openai-responses-http
        version: 2026.07.0
        digest: sha256:...
    labels:
      - core
      - streaming
      - function-calling
      - reasoning
      - state

  gates:
    - all_must_requirements_pass
    - no_client_parse_error
    - complete_tool_result_continuation
    - complete_isolated_edit_task

  sandbox:
    temporaryHome: true
    temporaryGitRepo: true
    network: target-only
    syntheticToolsOnly: true
~~~

Codex 官方配置当前声明 wire_api 只支持 Responses，并提供 SSE retry/idle timeout 和可选 Responses WebSocket 能力，因此 Codex profile 必须基于 Responses：[Codex Config Reference](https://developers.openai.com/codex/config-reference)。

OpenClaw profile 必须记录实际 Provider API 类型，不能把 native Ollama、OpenAI Chat、Responses、Anthropic Messages 混为同一 profile。OpenClaw 官方甚至明确提醒 Ollama 的 /v1 兼容接口可能破坏工具调用，证明真实 client profile 的必要性：[OpenClaw Ollama Provider](https://docs.openclaw.ai/providers/ollama)。

### 11.6 Profile 维护政策

- Tier 1 客户端在每次 release 解析并维护 previous/current 两个精确 stable 版本；candidate 只作非阻断 canary。
- 每个 profile 精确绑定 consumer version 或窄版本范围。
- 客户端更新后旧结果不得继承新 badge。
- Profile owner 负责在上游 release 后 14 天内评估更新。
- Proprietary CLI 大改时允许 temporary unsupported，但必须公开 Issue。
- 未获厂商认可时使用 community-tested with，不使用 certified by。

---

## 12. Wire Recorder、Evidence 与内部 IR

### 12.1 Wire 定义

Wire 指“某个明确 instrumentation layer 可观察的 HTTP/SSE/WebSocket 应用层数据和时序”，不是 TCP packet、TLS ciphertext 或物理网络 forensic。Go net/http、TLS termination、reverse proxy 与 transfer/content decoding 会改变 header 表示或 chunk 边界，因此报告必须声明 capture layer 和 instrumentation mode，不能笼统声称保存“网络原始字节”。

四个 capture layer：

| Layer | 观察点 | 可以宣称 | 不能宣称 |
|---|---|---|---|
| upstream_application_observation | Core transport 在 TLS/HTTP transfer framing 之后收到/发出的应用 payload | 该观察点的 body/SSE bytes、语义 header、时序 | TCP chunk、TLS、原 header 大小写/顺序 |
| proxy_forwarded_observation | Recording proxy 实际转发给 SDK/Client 的应用 payload | Client 下游收到的代理输出和重新分块 | 它与 upstream chunk boundary 一致 |
| client_sdk_observation | Driver/SDK 暴露的 event/object/error | 客户端真实解析结果 | SDK 未暴露的内部 raw bytes |
| sanitized_persisted_evidence | Redactor 后允许落盘的 projection | 可审计、可公开的保存内容 | 被删 secret/PII 的原值、完整原始流 |

instrumentation_mode 至少包含 direct_transport、recording_proxy、fixture_replay、client_native。每个 Evidence ID 绑定一个 layer；跨 layer 比较必须显式关联，不能把 proxy 重分块归咎于 provider。

记录：

- DNS/connect/TLS/first-byte 时间。
- HTTP method、URL、status。
- 语义 normalized headers；只有专用 lower-level adapter 实际观测到时才附加 source header representation。
- 选定 capture layer 的 request/response body byte ranges。
- SSE event/data/id/retry 行。
- chunk 的 monotonic time 和 byte offset。
- SDK event、parse error、retry、connection close、cancel。

HAR 只能作为辅助导出；权威格式使用 AAWire v1，因为 HAR 不能准确表达 SSE 生命周期、capture layer 和 client observation。

### 12.2 AAWire Event

~~~json
{
  "apiVersion": "urn:agentapi-doctor:wire:v1",
  "sequence": 42,
  "wall_time": "2026-07-10T12:00:00Z",
  "monotonic_ns": 45882000,
  "connection_id": "conn-1",
  "stream_id": "stream-1",
  "direction": "target_to_client",
  "capture_layer": "upstream_application_observation",
  "instrumentation_mode": "direct_transport",
  "layer": "sse",
  "kind": "data",
  "byte_offset": 1832,
  "payload_ref": "sha256:...",
  "payload_digest": "sha256:...",
  "source_payload_fingerprint": "local-hmac:...",
  "redactions": []
}
~~~

payload_digest 对应实际持久化的脱敏 payload。source_payload_fingerprint 是可选、本地、带密钥 HMAC，只用于判断 redaction 前内容是否相同；公共 artifact 禁止发布低熵 secret 的普通 hash。每条 assertion 引用 Evidence ID，不复制大段 payload。

### 12.3 Raw 与 Normalized 双轨

必须同时提供：

- source-faithful application observation：在选定 capture layer、redaction 前的有界内存观察；
- sanitized persisted evidence：唯一默认允许落盘的证据；
- normalized semantic IR：用于关系检查和跨实现差分。

“Source-faithful”只表示 recorder 在该应用层不主动修复、重排或吞掉 bytes；它不表示 TCP/TLS/header representation 无损。只有 synthetic-only 且 redactions 为空的 fixture，持久化 evidence 才能声明与该 capture layer byte-identical。其他运行的协议事实由 sanitized evidence、结构、时序和明确的 unavailable 字段共同表达。

Normalized IR 只包含：

- Interaction。
- Input/Output Item。
- Message/Content Part。
- Tool Call/Tool Result。
- Reasoning/opaque state artifact。
- Usage。
- Error。
- Stream lifecycle。

IR 必须保留：

- source protocol。
- capture-layer evidence pointer。
- provider extension。
- 原始类型。

例如 OpenAI arguments 是 JSON string、Gemini native args 是 object；IR 不能在归一化时吞掉这种 wire 差异。

### 12.4 Redaction

顺序：

~~~text
接收内存块
→ 认证 header/cookie/query/JSONPath 检测
→ redaction
→ 才允许落盘
~~~

默认永不持久化：

- Authorization、x-api-key、Cookie。
- OAuth token、refresh token。
- mTLS 私钥。
- 配置指定的敏感 header/query/path。

内容保存模式：

~~~text
metadata_only
standard_fixture_only
redacted_content
full_local_encrypted
~~~

公共上传只允许标准公开 fixture，或经 secret/PII scanner、人工确认后的合成内容。隐藏 reasoning 默认只保存 type、size、hash 和 opaque continuation，不保存内容。

### 12.5 Artifact Bundle

~~~text
.agentapi/runs/<run-id>/
├── plan.json
├── manifest.json
├── report.json
├── results.jsonl.zst
├── evidence/
├── wire/
├── sdk/
├── normalized/
├── repro/
├── logs/
└── signature/
~~~

大对象使用 SHA-256 CAS 去重；本地 SQLite 仅为可重建索引，不是权威数据源。Run ID 使用 UUIDv7 或 ULID；全局时间用 UTC，时序使用 monotonic clock。

### 12.6 Run Manifest

必须固定：

- Core version/commit/binary digest。
- Pack/profile/protocol snapshot digest。
- Driver image/executable/lockfile digest。
- SDK/runtime 版本。
- OS/arch/region。
- Target configuration fingerprint。
- 请求模型与响应模型。
- model/tokenizer/chat-template revision。
- parser/backend/quantization。
- temperature/top_p/seed。
- retry/concurrency/proxy/TLS。
- fixture digest。
- budget 和最终消耗。
- redaction/publication policy。

### 12.7 可重复性等级

| 等级 | 含义 |
|---|---|
| R0 Synthetic Byte Replay | synthetic-only、无 redaction，可在同一 application layer 重放完全相同 payload |
| R1 Sanitized Evidence Re-evaluation | 离线重算不依赖已删除字段的 oracle；不能声称重建原请求 |
| R2 Deterministic Fixture | 固定 Driver + fixture server，可重新执行 |
| R3 Version-Pinned Target | 模型、Runtime、配置均可固定 |
| R4 Opaque Provider | 只有 alias、region、时间和 observed fingerprint |
| R5 Insufficient Metadata | 缺少关键元数据 |

公共矩阵必须展示等级。云端 alias 滚动更新时不能承诺相同输出。

---

## 13. Oracle、Fuzz、Differential 与最小化

### 13.1 Oracle 类型

- TransportOracle。
- JSONSchemaOracle。
- EventFSMOracle。
- CrossFieldOracle。
- ToolLoopOracle。
- SDKParseOracle。
- MetamorphicOracle。
- DifferentialOracle。
- BehavioralStatisticalOracle。
- ProfileGateOracle。

Finding：

~~~json
{
  "assertion_id": "tool.arguments.type",
  "requirement_id": "OAI-CHAT-TOOL-006",
  "layer": "protocol",
  "verdict": "fail",
  "severity": "MUST",
  "category": "INVALID_FIELD_TYPE",
  "expected": "JSON string",
  "observed": "JSON object",
  "evidence_refs": ["sha256:..."],
  "source": {
    "uri": "urn:source:example"
  },
  "owner_hint": "serving-serializer",
  "attribution_confidence": 0.98
}
~~~

### 13.2 State Machine Oracle

OpenAI Responses 工具流示例：

~~~text
response.created
→ response.in_progress?
→ response.output_item.added(function_call)
→ response.function_call_arguments.delta*
→ response.function_call_arguments.done
→ response.output_item.done
→ response.completed | response.failed | response.incomplete
~~~

检查：

- sequence 单调。
- added/done 配对。
- item/index/call ID 唯一且引用合法。
- delta 只能引用已打开对象。
- arguments delta 可重建。
- terminal event 恰好一个。
- completed 后无语义事件。

### 13.3 Fuzz 面

1. Go parser native fuzz。
2. SDK Client + deterministic fixture server。
3. Target endpoint 安全黑盒 fuzz。
4. 历史真实失败 corpus regression。

JSON/Tool Schema 生成维度：

- nested object、array of object。
- enum、nullable、required、additionalProperties。
- Unicode、CJK、emoji、组合字符。
- 极大整数、浮点、负数。
- 空 object/array。
- 同名/近似工具名。
- 长 description、不同 property 顺序。
- 合法/非法 schema 对。

Streaming 生成维度：

- 每个字节切 chunk。
- 合并多个 SSE event。
- CRLF/LF。
- UTF-8 中间切分。
- 空/重复/未知 event。
- 丢失 done。
- 中途 EOF、timeout、cancel。
- 大 event、慢速流和 heartbeat。

Tool Loop：

- single/parallel/chained。
- result 乱序、重复、缺失。
- call ID 冲突或改变。
- arguments 多段/半截/非法 JSON。
- reasoning/tool/message 混合。
- 模型把工具 JSON 输出为普通文本。

### 13.4 核心 Properties

- 任意合法 chunk 切分，fold 后语义一致。
- added 最终有 done 或 terminal failure。
- function argument delta 拼接与 done 一致。
- call ID 在作用域内唯一。
- usage 非负且按协议自洽。
- 新 optional field/event 不导致 tolerant client 崩溃。
- 同 captured wire 重放给同 SDK/version 产生同一 client observation。
- stream accumulator 与同一条流的 final object 一致。

不能要求两次独立 live stream/non-stream 请求的文本完全一致；它们只做结构/关系层 metamorphic comparison。

### 13.5 Differential Testing

- 同一 captured wire → 不同 SDK/version。
- 同一 endpoint → raw decoder 与 SDK view。
- 同一 Scenario → 不同 serving runtime。
- 同一模型/runtime → 直连与 Gateway。

Differential 只发现 divergence，不以多数投票判真；最终由 Requirement/Oracle 裁决。

### 13.6 Reference 与 Mutant Server

项目必须内置：

- pack-conforming reference fixture server；只证明符合当前 pack 解释，不自称协议真理。
- 可组合 mutant server。

Mutation catalog 示例：

~~~text
arguments-object-instead-of-string
missing-output-index
duplicate-output-index
dropped-streaming-tool-call
invalid-finish-reason
missing-terminal-event
duplicate-terminal-event
tool-call-id-changed
unknown-event-crashes-client
unclosed-reasoning-block
usage-inconsistent
truncated-utf8
~~~

要求：

- Pack-conforming reference server 全部通过。
- 每个 mutant 能被预期 test 捕获。
- 每个核心 test 至少 kill 一个相关 mutant。
- Mutant 只引入一个主故障，避免归因模糊。

Reference、Oracle 和 Mutant 由同一解释生成只能证明内部一致性，不能证明解释正确。每个 Tier 1 requirement family 还必须：

- 至少一名非实现者做 protocol/source review；
- 用至少一个独立实现或公开历史 fixture 做交叉验证；
- 在许可与预算允许时，对官方服务/SDK做 differential canary，但不得把官方实测自动升级为 normative；
- 对 reference、官方行为和文字规范冲突创建 SPEC_AMBIGUITY；
- pack release evidence 同时保存 interpretation review，而不只保存 mutation score。

### 13.7 Failure Fingerprint

~~~text
hash(
  scenario_id,
  assertion_id,
  failure_category,
  normalized_expected_actual_diff
)
~~~

Fingerprint 用于跨版本归并相同失败，不包含时间、request ID 等不稳定字段。

### 13.8 Failure Minimizer

两阶段：

1. 先离线缩减 captured response/events。
2. 只有必须找到 request 诱因时才进行受预算约束的 live minimization。

Request shrinker：

- 删除无关 message/tool/optional 参数。
- 缩减 schema、prompt 和历史轮次。
- parallel 缩减到最小失败组合。

Stream shrinker：

- 删除无关 event/field。
- 合并/重切 chunk。
- 缩短 arguments。
- 保留最小失败状态机前缀。

采用 ddmin + AST-aware shrink。Live predicate 用 k-of-n；预算不足时返回 verdict=inconclusive、reason_code=insufficient_samples；失败概率不稳定则额外记录 flaky_detected Operational Reliability 标签。

### 13.9 Repro Bundle

~~~text
repro/
├── README.md
├── manifest.json
├── request.json
├── response.aawire.jsonl.zst
├── response.sanitized.txt
├── curl.sh
├── python.py
├── node.mjs
├── client-profile.yaml
├── expected-finding.json
└── verify.sh
~~~

脚本只通过环境变量读取 key。README 自动包含：

- 环境/版本。
- 启动参数。
- 期望与实际。
- 规范链接。
- 最小重现步骤。
- 故障域证据。
- 建议提交的上游 repo。

---

## 14. 跨协议测试 Taxonomy

### 14.1 Endpoint 与发现

- Base URL 尾部斜杠和 /v1 拼接。
- Endpoint path、method、query、Accept、Content-Type。
- /models 列表、单模型读取、模型 ID 编码。
- 不存在模型、模型 alias 和实际返回模型。
- 自定义 header/query。
- HTTP/1.1、HTTP/2；WebSocket 独立 pack。
- TLS、SNI、自定义 CA、mTLS、代理。
- gzip/br 解压、chunked transfer。
- IPv4/IPv6/localhost。
- Redirect 后敏感 header 不跨域泄漏。
- DNS/connect/TLS/TTFB/stream idle timeout。

/models 只能作为发现信号，不能据此推断 tools、vision、reasoning 或 structured output。

### 14.2 认证与版本

- Bearer、自定义 header。
- Anthropic x-api-key、anthropic-version、beta header。
- Gemini x-goog-api-key/query key、Api-Revision。
- Azure/Bedrock/Vertex 独立 Provider Profile。
- 缺失、无效、过期 token。
- 401/403 区分。
- credential helper refresh。
- 报告和日志自动脱敏。

### 14.3 HTTP、JSON 与前向兼容

- UTF-8、CJK、emoji、组合字符。
- 转义、反斜杠、换行、零字符。
- null/空字符串/空数组/空对象差异。
- 数字精度、重复 JSON key、非法/截断 JSON。
- 未知 request field。
- 未知 optional response field/event。
- Content-Length/chunked/keep-alive。
- response/event/header 最大尺寸。
- 慢速流、压缩炸弹和异常 content type。

未知 optional 字段应被记录并安全保留；如果协议允许扩展，客户端不得因此崩溃。

### 14.4 Message 与角色

- system/developer/user/assistant/tool/model 等协议特定角色。
- string content 与 content-part array。
- 空 content。
- 多轮角色顺序。
- tool call 后 tool result。
- 多 result 的顺序与关联。
- text/media 混合。
- Anthropic 顶层 system。
- Gemini user/model 和 function response part。
- Responses message/function_call/function_call_output/reasoning item。

### 14.5 普通非流式输出

- 必需 ID/object/model/created/status。
- choices/output/content/candidates/steps。
- index 连续性和唯一 ID。
- 多 candidate/choice。
- text/refusal/tool/reasoning 混合。
- 完成、截断、拒绝、过滤状态。
- output item 与 call/result 引用完整性。
- model requested 与 model reported。

### 14.6 SSE / Streaming

- Content-Type: text/event-stream。
- LF/CRLF。
- event/data/id/retry 语义。
- 一个网络 chunk 多 event。
- 一个 event 跨任意 byte chunk。
- UTF-8 字符跨 chunk。
- JSON string 跨 chunk。
- 空 delta、ping、heartbeat/comment。
- HTTP 200 后 stream error。
- 突然 EOF。
- 缺失、重复、乱序 terminal event。
- backpressure、slow reader、client disconnect。
- cancellation 和 completion race。
- stream fold 与该流 final object 一致。
- 未知新增 event 安全处理。

项目提供 transport mutation proxy，对合法 fixture 自动 rechunk，以发现依赖偶然 chunk 边界的 parser。

### 14.7 Tool / Function Calling

- 无工具、一个、多工具。
- none/auto/required/any/named。
- allowed tools/tool allowlist。
- 工具名长度、大小写和边界字符。
- 空参数工具。
- required/optional/nullable。
- nested object、array of object、enum。
- Unicode、大 arguments。
- single/parallel/chained。
- 同一输出 text + tool call。
- tool call → result → final answer。
- call ID 唯一、关联正确。
- result 乱序、重复、缺失、unknown ID。
- tool error/is_error。
- result 为 empty/text/JSON/image。
- arguments streaming 重建。
- strict schema。
- tool call 中途 refusal/truncation。
- raw tool JSON 泄漏到普通 content。
- 无限 tool loop 检测。

Client tool、Provider server-side tool、remote MCP tool 必须分开；执行责任与 wire 形态不同。

### 14.8 Structured Output

JSON mode 与 strict schema 分开：

- JSON mode 只保证合法 JSON。
- Structured Output 保证某个支持子集中的 Schema。
- primitive/object/array。
- nested、enum、const、nullable、anyOf、$defs/$ref。
- required/additionalProperties。
- string/numeric/array constraints。
- 最大深度、property 和 enum 数。
- 无效或不支持 Schema。
- streaming partial JSON。
- max token 导致半截 JSON。
- refusal 是否绕过 Schema。

不同协议和模型只支持 JSON Schema 子集。property 顺序默认只做诊断，不能作为跨 Provider 通用合规条件。OpenAI 官方 Structured Outputs 文档还建议依赖 SDK 处理 streaming，并强调语言类型与 Schema 防漂移：[OpenAI Structured Outputs](https://developers.openai.com/api/docs/guides/structured-outputs)。

需要分别保存：

- 用户原始 Schema。
- SDK 实际发出的 Schema。
- 服务端 raw response。
- SDK 本地 validation 结果。

### 14.9 State 与多轮

- 完全 stateless 手工回传。
- previous_response_id / previous_interaction_id。
- store=true/false。
- 不存在、过期、跨账户 previous ID。
- 同一 previous ID 分支继续。
- 并发 continuation。
- tool call continuation。
- retrieve/delete/cancel/background。
- 断流恢复 cursor（若协议支持）。
- opaque reasoning/thought artifact 原样回传。

不读取或评价隐藏 CoT，只验证公开 summary 和 opaque artifact 的类型、签名/引用和 continuation。

### 14.10 Error 与 Retry

- 400、401、403、404、409、413、422、429、500/502/503。
- Anthropic overloaded 等协议特定状态。
- HTTP 200 后 SSE error。
- error content type、结构、request ID。
- Retry-After 和 rate-limit headers。
- SDK 自动 retry 是否可见。
- retry 上限和退避。
- 非幂等请求不做无条件自动重试。
- retry 不导致重复工具执行。

Transient error 产生 verdict=inconclusive、reason_code=transient_error，不直接计为协议不兼容。

### 14.11 Usage

- input/output/total 的结构与自洽性。
- cached、reasoning、audio/image usage。
- streaming usage 的出现位置。
- 终止前 null 的合法情况。
- retry、多轮、stateful。
- tool/server-tool usage。
- count-token endpoint（若协议提供）。

不要求跨 Provider token 数完全相同；tokenizer、隐藏 prompt、缓存和 reasoning 口径不同。

### 14.12 Multimodal

- 图片 URL、inline Base64、file ID。
- MIME、损坏、过大资源。
- 多图片和 part 顺序。
- text/image/document/audio/video。
- multimodal tool result。
- text/audio/image output。
- streaming binary/Base64 delta。
- 外链授权/过期/下载失败。

标准 fixture 优先使用极小 inline canary，避免 DNS、CDN 和第三方网络变量。

### 14.13 Reasoning / Thinking

- effort/level/budget。
- 不支持参数组合的清晰错误。
- summary 与 hidden reasoning 分离。
- summary streaming。
- encrypted reasoning/redacted thinking。
- Anthropic signature delta。
- Gemini thought signature。
- stateless continuation 原样回传。
- model switch 后 opaque artifact 行为。
- usage 中 reasoning/thought token。

### 14.14 Cancel、Timeout 与资源释放

区分：

1. 客户端关闭连接。
2. 协议级 cancel。
3. background task cancel。

测试首 token 前、文本中间、tool arguments 中间 cancel；race、幂等 cancel、资源释放、goroutine/file descriptor 泄漏和取消后事件。显式 background cancel 不能错误要求于普通 streaming。

---

## 15. Protocol Pack 详细设计

### 15.1 OpenAI Chat Completions

核心路径：

~~~text
POST /v1/chat/completions
~~~

覆盖：

- messages、roles、content parts。
- n choices。
- finish_reason：stop、length、content_filter、tool_calls、legacy function_call。
- max_completion_tokens 和兼容字段。
- tools、tool_choice、parallel_tool_calls。
- tool_calls[].function.arguments 的 wire 类型为 JSON string。
- tool role、tool_call_id。
- response_format json_object/json_schema。
- refusal、annotations、usage。
- multimodal 作为 capability。

Streaming 状态：

~~~text
chat.completion.chunk*
→ optional usage-only chunk
→ data: [DONE]
~~~

断言：

- 同 choice 的 stream ID/index 稳定。
- delta.role 可只在首 chunk。
- tool_calls[].index 能重建并行调用。
- ID/name 可只在早期 chunk。
- arguments 为字符串片段。
- finish_reason 只在结束阶段。
- include_usage 的最终 chunk 可有空 choices。
- [DONE] 后无语义数据。

OpenAI 官方 function calling 定义了 tools → tool call → application execution → tool output → final response 的多步流程，并以 call ID 关联结果：[OpenAI Function Calling](https://developers.openai.com/api/docs/guides/function-calling)。

### 15.2 OpenAI Responses HTTP/SSE

核心路径：

~~~text
POST /v1/responses
~~~

Responses 的原子单位是 typed Item，不是 Chat choices：

- message。
- function_call。
- function_call_output。
- reasoning。
- refusal/content part。
- built-in/remote MCP tool items。

覆盖：

- input string/items、instructions。
- output item array。
- name/call_id/arguments。
- function result 关联。
- previous_response_id、store。
- stateless reasoning artifact。
- structured output 使用 text.format。
- background/retrieve/cancel/resume 独立 capability。
- output_text 是 SDK convenience，不是 wire 真值。

文本 SSE：

~~~text
response.created
→ response.in_progress?
→ response.output_item.added
→ response.content_part.added
→ response.output_text.delta*
→ response.output_text.done
→ response.content_part.done
→ response.output_item.done
→ response.completed
~~~

工具 SSE：

~~~text
response.output_item.added(function_call)
→ response.function_call_arguments.delta*
→ response.function_call_arguments.done
→ response.output_item.done
→ response.completed
~~~

终止：

~~~text
response.completed
| response.failed
| response.incomplete
| error
~~~

关键断言：

- sequence_number 单调。
- item_id 先创建后引用。
- 每个 item/content part 只关闭一次。
- delta 只作用于 open item。
- arguments 最终为可解析 JSON string。
- terminal 前所有 item 闭合。
- terminal 恰好一个。
- incomplete_details 与 status 一致。

官方迁移指南明确提醒不要把所有 output 当 message、不能丢 reasoning/function items、tool output 必须匹配 call_id，且 Responses streaming 使用 typed events：[Responses Migration](https://developers.openai.com/api/docs/guides/migrate-to-responses)。

### 15.3 Codex Profile

当前 Codex custom provider 只接受 Responses wire API，profile 至少包括：

- 自定义 base URL/env key。
- Responses HTTP/SSE。
- 可选 WebSocket。
- reasoning effort/summary。
- single/multi tool。
- tool result continuation。
- retry、stream idle。
- 临时 Git repo 中读取文件。
- 运行无副作用命令。
- 修改 canary 文件。
- 验证最终内容和 Git diff。
- 长 session 与多轮状态。

Profile 全程使用临时 HOME/repo、无真实 secrets、默认无外网。

### 15.4 Anthropic Messages

核心：

~~~text
POST /v1/messages
anthropic-version: 2023-06-01
~~~

Beta feature 作为独立 profile/header，不静默并入基础包。

覆盖：

- 顶层 system。
- user/assistant content blocks。
- max_tokens。
- tool input_schema、tool_choice。
- tool_use id/name/input object。
- tool_result tool_use_id/content/is_error。
- client/server tools。
- parallel/strict tools。
- structured output。
- thinking/signature。
- prompt cache usage。

Stop reason：

- end_turn。
- max_tokens。
- stop_sequence。
- tool_use。
- pause_turn。
- refusal。
- model_context_window_exceeded。

SSE：

~~~text
message_start
→ (
    content_block_start(index)
    → content_block_delta(index)*
    → content_block_stop(index)
  )*
→ message_delta+
→ message_stop
~~~

规则：

- ping 任意位置合法。
- error 可在 HTTP 200 后出现。
- 未知新增 event 不能令 tolerant client 崩溃。
- message_delta usage 为累计。
- input_json_delta.partial_json 是字符串片段。
- tool_use.input 最终为 object。
- thinking 可有 thinking_delta/signature_delta。

官方说明：[Anthropic Streaming Messages](https://platform.claude.com/docs/en/build-with-claude/streaming)、[Tool Use](https://platform.claude.com/docs/en/agents-and-tools/tool-use/overview)。

### 15.5 Google generateContent 与 Interactions

二者必须是独立 pack，不能互为别名。

generateContent：

- contents、user/model roles、parts。
- system instruction。
- text/inlineData/fileData。
- candidates/index/finishReason/promptFeedback。
- usageMetadata/modelVersion/responseId。
- function declarations、functionCall args object、functionResponse。
- parallel/compositional function calling。
- structured output、thinking、thought signature。
- streamGenerateContent 聚合。

Google native function args 是 object，与 OpenAI JSON string 不同，必须保留。

Interactions：

- input string/typed steps。
- steps、previous_interaction_id、store。
- function_call/function_result。
- server-side tools。
- background、structured/multimodal output。
- thought step/signature。

Streaming：

~~~text
interaction.created
→ step.start(index)
→ step.delta(index)*
→ step.stop(index)
→ interaction.completed
~~~

每个 index 只能 start/stop 一次，delta 只引用 open step，arguments_delta 可重建，function_call continuation ID 正确，未知 step/delta 前向兼容。官方资料：[Gemini Function Calling](https://ai.google.dev/gemini-api/docs/function-calling)、[Gemini Streaming](https://ai.google.dev/gemini-api/docs/streaming)。

### 15.6 MCP Extension Pack

需要区分：

1. MCP Client/Server Protocol Conformance。
2. LLM Provider 的 Remote MCP Connector。

默认稳定基线固定到 MCP 2025-11-25：[MCP Specification](https://modelcontextprotocol.io/specification/2025-11-25)。

MCP Protocol Pack：

- JSON-RPC request/response/notification/error。
- initialize/version/capability negotiation。
- stdio 与 Streamable HTTP。
- session、MCP-Protocol-Version、Last-Event-ID。
- tools list/call/inputSchema/outputSchema/structuredContent/isError。
- resources/prompts/roots/sampling/elicitation/logging/progress/cancel/tasks。
- OAuth 2.1、PKCE、Resource Metadata/Indicators、audience binding。
- Origin/DNS rebinding 防护。

Provider Remote MCP Connector Profile：

- OpenAI Responses connector。
- Anthropic beta connector。
- Google connector。

Provider 明确不支持某 transport 时更新对应 CapabilityStatus=unsupported，相关 ResolvedScenario 使用 plan_disposition=not_applicable、reason_code=unsupported_capability，而不是基础协议 FAIL。

### 15.7 Extension Pack 原则

Embeddings、Batch、Files、Realtime、图像/视频生成等：

- 独立 pack、独立 badge。
- 不计入 Agent-ready core。
- 默认关闭付费/副作用测试。
- 使用独立维护者和预算。

---

## 16. SDK 与真实 Client Matrix

### 16.1 官方 SDK Driver 必测

- 普通同步/异步请求。
- streaming iterator/accumulator。
- tool call parser。
- structured-output helper。
- cancel/AbortController。
- error subclass。
- retry。
- raw response access。
- SDK 对 request/schema 的实际变换。

每个 Driver 固定 package lock、Python/Node/Go runtime、SDK 精确版本和 image digest。

### 16.2 Vercel AI SDK

- @ai-sdk/openai 的 Responses 默认路径。
- 显式 OpenAI Chat。
- @ai-sdk/openai-compatible。
- generateText/streamText。
- structured output。
- tool calls、multi-step、partial tool input。
- usage/provider metadata。
- abort signal。

Vercel 提供单独的 OpenAI-compatible Provider，说明客户端对兼容 endpoint 有明确生产需求：[Vercel OpenAI-compatible Provider](https://ai-sdk.dev/providers/openai-compatible-providers)。

### 16.3 OpenClaw

记录 API 类型：

~~~text
openai-responses
openai-completions
anthropic-messages
ollama-native
gemini-native
plugin-provider
~~~

支持层级不能由这个枚举暗示。P04 的 OpenClaw Tier 1 只覆盖绑定到 core packs 与精确 support lock 的 `openai-responses`、`openai-completions`、`anthropic-messages` profiles。`ollama-native` 与 `gemini-native` 属于 P06 的独立 Tier 2 profiles；`plugin-provider` 只有在存在独立 ProtocolPack、来源锁、owner 和完整 gate 时才逐个声明，不提供“任意插件均兼容”的泛化结论。

测试：

- Provider 初始化和 model discovery。
- tool schema 转换。
- content string/parts。
- strict message keys。
- streaming usage。
- reasoning/thinking。
- single/multi tool loop。
- continuation、timeout、fallback。
- 真实 OpenClaw agent loop，而不是只测内部 HTTP API。

### 16.4 Claude Code

Claude Code profile 只对官方公开的 Anthropic-format Gateway/custom base URL 路径声明兼容，不宣称能直接消费任意 OpenAI-compatible endpoint。需要固定 Claude Code 版本、Gateway 文档契约和 Anthropic Messages pack；若客户端许可不允许重分发，调用用户本地安装。

### 16.5 LangGraph / OpenAI Agents SDK

它们属于应用框架 profile：

- 固定框架及 provider adapter 版本。
- 运行确定性工具图。
- 分别保存框架 trace 和 capture-layer application evidence。
- 不把框架自己的 orchestration 错误归为 endpoint protocol。

---

## 17. Report、CLI 与 Config

### 17.1 CLI

~~~text
doctor init [<directory>]
doctor self-check

doctor target add <name> --base-url <url> [--protocol <id>] [--model <id>] [--auth-ref <secret-ref>]
doctor target list
doctor target inspect <target>
doctor target probe <target> --intent-plan <path> --output <path>

doctor pack search <query>
doctor pack pull <ref>
doctor pack list
doctor pack inspect <ref>
doctor pack validate <path>
doctor pack verify <ref>

doctor profile list
doctor profile inspect <ref>
doctor profile validate <path>

doctor test <target> [--pack <ref>] [--profile <ref>] [--scenario <id>] [--plan-only [--resolve]] [--output <path>]

# <run-ref> := <run-id> | latest；run-id 语法为 UUIDv7/ULID，永远不等于保留词 latest
doctor run inspect <run-ref>
doctor replay <run-ref>
doctor minimize <run-ref> --finding <id>
doctor compare <run-ref> <run-ref>

doctor baseline accept <run-ref> --name <name>
doctor baseline list
doctor baseline inspect <name>
doctor baseline compare <run-ref> --baseline <name>
doctor report terminal|json|junit|sarif|markdown|html <run-ref> [--output <path>]
doctor repro <run-ref> --finding <id>

doctor publish <run-ref> [--registry <url>]
doctor registry login [--registry <url>]
doctor registry status [--registry <url>]
doctor matrix query [--protocol <id>] [--profile <ref>] [--subject <name>] [--format terminal|json|markdown]

doctor dev scaffold <requirement|scenario|fixture|profile|driver> <name> --output <directory>
doctor migrate <artifact> --to <schema-ref> --output <path>
doctor completion <bash|zsh|fish|powershell>
doctor version
~~~

仓库维护者的 control-plane 命令也进入 `cli/spec.yaml`，但属于受保护 workflow surface，不承诺普通用户可直接把状态改为通过：

~~~text
doctor phase state-verify
doctor phase control-plane-verify
doctor phase activate <phase> --unit <unit> --attestation <path>
doctor phase resume <phase> --unit <unit> --attestation <path>
doctor phase gate-unit <unit> --output <directory>
doctor phase gate <phase> --output <directory>
doctor phase evidence-verify <phase> --evidence <path>
doctor phase ga-gate --output <directory>
~~~

根目录 `make state-verify`、`make control-plane-verify`、`make gate-unit`、`make gate`、`make evidence-verify`、`make ga-gate` 只是这些版本化命令的薄封装，不另造状态语义。

最终品牌确定前，二进制名可暂用 doctor；不要使用单独 agentapi，因为已有 coder/agentapi 项目。

命令 reference 由 machine-readable CLI spec 生成；上面不是省略 operand 的伪语法。方括号表示真正 optional；竖线只表示闭合枚举。所有读取 Run 的命令都要求位置参数 `<run-ref>`；跨 Bash/zsh/fish/PowerShell 都使用裸保留词 `latest`，因此 `doctor compare latest <run-id>` 与 `<run-id> latest` 无歧义，CI 禁止 `latest`。`--resolve` 只允许与 `--plan-only` 同时使用。破坏 subcommand、operand、flag/default 或 JSON output 需要 major/deprecation 流程。

### 17.2 Config

优先级：

~~~text
CLI flag
> environment
> project .agentapi/config.yaml
> user config
> compiled default
~~~

~~~yaml
apiVersion: urn:agentapi-doctor:config:v1beta1

targets:
  local-vllm:
    baseURL: http://127.0.0.1:8000/v1
    protocol: openai-responses
    model: Qwen/Qwen3.5-32B
    auth:
      type: bearer
      token:
        ref: env://LOCAL_LLM_API_KEY
    metadata:
      runtime: vllm
      runtimeVersion: ...
      toolParser: qwen3

defaults:
  profile: codex.responses
  budget:
    maxRequests: 80
    maxDuration: 15m
    maxInputTokens: 100000
    maxOutputTokens: 20000
  capture:
    content: standard_fixture_only
  retries:
    transport: 1
    semantic: 0
~~~

Secret Reference：

- env://
- keyring://
- file://（强制权限检查）
- exec://（默认关闭，显式启用）

exec:// 只属于用户本地高风险 secret resolver，不属于安全的声明式 Scenario/Pack；启用时固定 executable digest、禁用 shell expansion、使用参数数组、限制环境/timeout/stdout size，并在报告标记。project-operated runner 永久禁用。

配置中检测到明文 key 时警告或拒绝公共发布。Effective config 可打印，但必须脱敏。

### 17.3 运行计划

Planning 是两阶段 contract：

1. IntentPlan：离线、不可变，固定用户选择的 target、pack/profile、允许的 capability probe、最大预算、候选 denominator 与条件分支；
2. CapabilityObservation：在 IntentPlan 明确允许的 probe/budget 内收集，只是证据；
3. ResolvedRunPlan：versioned resolver 根据 IntentPlan + CapabilityObservation + support/pack digest，明确列出每个 scenario 的 execute/skip/not-applicable、原因和最终 denominator；
4. 执行只接受已签名的 ResolvedRunPlan digest，结果同时引用 IntentPlan 和 CapabilityObservation digests。

test 前输出：

- 将运行的 Scenario、Plane、Driver。
- 预计最大请求/token/时间。
- 可选和跳过能力、probe evidence 与最终 denominator。
- 可能使用的 secret/网络权限。
- 是否可上传。

`doctor test <target> --plan-only` 默认不出网并生成 canonical IntentPlan。加入 `--resolve` 后可在明确授权下执行 probe 并生成 ResolvedRunPlan；CI 可以分别审批两个 digest。Capability probe 不能修改 IntentPlan，resolver 不能选择 contract 未预先允许的分支；CapabilityObservation 变化必须产生新的 ResolvedRunPlan，不得复用旧签名。

### 17.4 Exit Codes

| Code | 含义 |
|---:|---|
| 0 | 所有 hard gates 通过 |
| 1 | Target/Profile 存在失败 |
| 2 | Config/DSL/用户输入错误 |
| 3 | Harness/Driver/基础设施错误 |
| 4 | 预算耗尽或关键结果 inconclusive |
| 5 | 认证/权限失败 |
| 6 | Baseline regression gate 失败 |
| 130 | 用户 SIGINT；partial artifact 已尽力 finalize |

多条件优先级固定为：用户/config 输入错误 2 > auth/permission 5 > harness/driver/infrastructure 3 > incomplete/budget 4 > baseline regression 6 > target/profile fail 1 > success 0。SIGINT 单独返回 130；若报告已完成仍记录所有底层 condition。Stable JSON 同时输出 primary_exit_code 和 conditions[]，不因优先级丢掉 target finding。Exit code 是 stable public API。

### 17.5 报告格式

- Terminal。
- Stable JSON。
- JUnit XML。
- SARIF。
- Markdown。
- 单文件离线 HTML。
- HAR 辅助导出。
- OpenTelemetry OTLP 可选。

HTML 必须转义所有 Provider 内容并使用严格 CSP。SARIF 只用于 CI annotation，不把 endpoint finding 伪装成源代码漏洞。

### 17.6 Baseline Diff

~~~text
NEW_FAILURE
REGRESSION
FIXED
UNCHANGED
NEW_CAPABILITY
NO_LONGER_TESTED
~~~

Baseline 绑定 pack/profile digest。测试集合变化后不得直接比较旧/new 百分比分母。

---

## 18. 历史故障 Corpus

首发前至少收集 30 个一手上游问题，创建原始、脱敏、最小 fixture。种子列表：

| 故障 | 目标测试 |
|---|---|
| [vLLM #39584](https://github.com/vllm-project/vllm/issues/39584) parallel tool delta 导致 Responses stream 崩溃 | 多调用拆分、terminal 完整性 |
| [vLLM #45742](https://github.com/vllm-project/vllm/issues/45742) content index 导致 OpenAI SDK IndexError | content index 状态机与 SDK replay |
| [vLLM #31871](https://github.com/vllm-project/vllm/issues/31871) stream 输出原始 tool XML | stream/non-stream tool parser 差分 |
| [vLLM #17614](https://github.com/vllm-project/vllm/issues/17614) streaming 参数被截断 | arguments delta 重建 |
| [llama.cpp #20607](https://github.com/ggml-org/llama.cpp/issues/20607) Responses event 缺字段 | output/item/content index |
| [llama.cpp #20198](https://github.com/ggml-org/llama.cpp/issues/20198) arguments 类型错误 | string vs object |
| [llama.cpp #20359](https://github.com/ggml-org/llama.cpp/issues/20359) stream/non-stream tool args 非法 | JSON parse 与等价性 |
| [llama.cpp #18591](https://github.com/ggml-org/llama.cpp/issues/18591) 并行调用 index 全为 0 | tool_calls index 唯一性 |
| [llama.cpp #20090](https://github.com/ggml-org/llama.cpp/issues/20090) Anthropic thinking 在转换中丢失 | opaque reasoning continuity |
| [LiteLLM #30762](https://github.com/BerriAI/litellm/issues/30762) streaming tool calls 静默丢失 | raw/provider/client 三视图 |
| [LiteLLM #21041](https://github.com/BerriAI/litellm/issues/21041) tool call finish_reason=stop | terminal reason 与工具存在关系 |
| [LiteLLM #19789](https://github.com/BerriAI/litellm/issues/19789) malformed function call 被映射为成功 stop | upstream error preservation |
| [Ollama #14493](https://github.com/ollama/ollama/issues/14493) Qwen tool/reasoning 格式问题 | parser、reasoning block closure |
| [Google GenAI Python #2575](https://github.com/googleapis/python-genai/issues/2575) streaming automatic function calling 空结果 | SDK/client observation |

每个 corpus entry 必须记录：

~~~text
source_issue
affected_version
fixed_version
minimal_reproduction
expected_failure_fingerprint
license_and_provenance
redaction_status
upstream_owner
~~~

不直接复制用户私有日志；根据公开 Issue 自行重写最小合成 fixture。

---

## 19. 公共 Compatibility Registry

### 19.1 目标与非目标

Registry 不是排行榜，而是可验证的兼容性观测数据库。它回答：

- 某个明确版本、明确配置的目标，通过了哪个不可变测试集合；
- 谁运行、何时运行、用什么 runner 与 driver 运行；
- 结果是否可复现、是否新鲜、是否经目标所有者确认；
- 失败证据能否被第三方独立下载并重跑；
- 后续版本是否修复或重新引入同一失败。

Registry 不做：

- 不把模型回答质量与 API 契约兼容性混成单一分数；
- 不宣布某实现“官方认证”，除非对应标准组织明确授权；
- 不扫描任意公网 URL；
- 不允许厂商付费改变结果、排序、徽章或争议结论；
- 不保留未经同意的 prompt、completion、密钥或个人数据。

### 19.2 核心数据对象

最小不可变单位是 Compatibility Observation：

~~~json
{
  "schema_version": "urn:agentapi-doctor:observation:v1",
  "observation_id": "sha256:...",
  "observation_class_id": "sha256:...",
  "equivalence_profile": {
    "name": "strict-client-environment",
    "version": "1.0.0",
    "digest": "sha256:..."
  },
  "subject": {
    "project": "example/runtime",
    "version": "1.8.2",
    "identity_level": "version-pinned",
    "artifact_digest": "sha256:...",
    "observed_fingerprint": "sha256:...",
    "deployment": "self-hosted",
    "model": "example-model",
    "config_digest": "sha256:..."
  },
  "test": {
    "pack": "openai-responses-http",
    "pack_version": "2026.07.0",
    "pack_digest": "sha256:...",
    "profile": "codex.responses",
    "profile_version": "1.0.0",
    "profile_digest": "sha256:...",
    "consumer": {
      "kind": "agent-client",
      "name": "codex-cli",
      "version": "0.144.1",
      "package_digest": "sha256:...",
      "executable_digest": "sha256:...",
      "runtime": "native",
      "runtime_version": "exact-value"
    },
    "driver": "codex-driver",
    "driver_version": "0.4.1",
    "driver_digest": "sha256:...",
    "runner_version": "1.0.0",
    "runner_digest": "sha256:...",
    "core_digest": "sha256:...",
    "oracle_digest": "sha256:..."
  },
  "environment": {
    "os": "linux",
    "arch": "amd64",
    "region": "self-reported",
    "started_at": "RFC3339 timestamp",
    "network_policy": "registry-egress-v1"
  },
  "result": {
    "profile_outcome": "incompatible",
    "dimensions": {
      "transport": "pass",
      "protocol": {
        "summary": "fail",
        "wire_syntax": "pass",
        "interaction_semantics": "fail"
      },
      "model_behavior": {
        "summary": "not_run",
        "task_completion": "not_run"
      },
      "client_compatibility": "fail",
      "operational_reliability": "not_run"
    },
    "verdict_counts": {
      "pass": 0,
      "fail": 0,
      "warn": 0,
      "inconclusive": 0
    },
    "plan_disposition_counts": {
      "execute": 0,
      "skip": 0,
      "not_applicable": 0
    },
    "execution_counts": {
      "completed": 0,
      "skipped": 0,
      "cancelled": 0,
      "errored": 0
    }
  },
  "provenance": {
    "submitter": "identity",
    "attestation_uri": "oci://...",
    "signature": "sigstore bundle reference"
  },
  "artifacts": {
    "manifest": "oci://...",
    "manifest_digest": "sha256:...",
    "redaction_policy": "strict-v1",
    "retention_class": "public-minimal"
  },
  "registry_derived": {
    "trust_labels": ["owner-verified"],
    "freshness": "fresh",
    "published_at": "RFC3339 timestamp"
  }
}
~~~

规则：

- observation_id 是一次具体运行的规范化 immutable projection 摘要，不是数据库自增 ID；
- observation_class_id 按 versioned equivalence_profile 聚合真正等价的独立运行；
- self-hosted subject、pack、profile、resolved consumer/package/executable、driver、runner、core、oracle、配置必须精确到版本和/或 digest；R4 opaque provider 无法提供 artifact digest 时必须 identity_level=opaque、带 alias/region/time/observed_fingerprint，不能伪造精确版本；
- 不可变记录不得原地修改。修正通过 supersedes、tombstone 或 dispute 记录追加；
- scenario 明细必须带 requirement ID、assertion ID、evidence pointer、状态与原因；
- 未运行、能力不适用、环境阻塞、预算耗尽必须分别表示，绝不能算作 pass；
- 所有比例的分母必须展示，且与 pack/profile digest 绑定。

Hash projection：

- observation_id 输入包含 schema version、subject、test、environment、result、manifest_digest；
- 明确排除 observation_id 自身、signature/attestation URI、trust/freshness、published_at、dispute 和 supersession；
- 默认 observation_class_id 输入包含 subject/version/config/model、gateway chain、region、OS/arch、resolved consumer/package/executable、SDK runtime/toolchain、transport、capture layer/instrumentation、pack/profile/driver/core/oracle 和 scenario denominator digest；只排除 wall-clock time、submitter、runner instance ID、签名与单次 result；
- Profile 可为明确的跨平台 metamorphic study 定义另一套 equivalence_dimensions，但必须发布新 equivalence profile/version/digest，不能事后忽略差异来凑独立重现；
- provenance attestation 是对 observation_id 的独立多值关系；重复转发同一 observation 不增加独立重现，独立 runner 会产生不同 observation_id 但可属于同一 class；
- Registry 只按 exact observation_id 去重，不把不同 provenance 或独立运行覆盖。

Canonicalization 前拒绝重复 JSON key、NaN/Infinity、超出 schema 的 number、非规范 RFC3339 时间、YAML 隐式歧义类型和 Unicode 非法序列。Hash projection、canonicalization 和 observation_class 算法是 v1 public contract。

### 19.3 五维结果，不设总冠军

公共页面与第 4 节使用同一组五个顶层维度：

1. Transport：连接、HTTP、SSE/WebSocket framing、终止与取消；
2. Protocol：字段/类型/枚举的 wire syntax，以及状态、工具调用、结构化输出、usage 等 interaction semantics；页面同时显示两个子维度；
3. Model Behavior：受控任务完成率、工具选择与参数语义，必须显示重复次数和置信区间；
4. Client Compatibility：真实 SDK 或 Agent 客户端所观察到的解析、重试、取消和完整 loop；
5. Operational Reliability：重复运行的 flakiness、429/5xx、资源释放与独立性能诊断。

允许用户按 protocol、profile、client、版本、运行方式筛选；不提供把所有维度压缩成一个“兼容度冠军”的默认排序。Badge 必须显示 profile 与完整 pack CalVer，例如 `codex.responses 1.0.0 / openai-responses-http 2026.07.0`，而不是模糊的 OpenAI compatible。

### 19.4 信任等级

| 等级 | 定义 | UI 标签 | 允许的声明 |
|---|---|---|---|
| Local | 只存在于用户本机 | Local only | 无公共声明 |
| Self-reported | 提交者签名，但未证明目标所有权 | Self-reported | “有人提交了此结果” |
| Owner-verified | 通过 DNS TXT、GitHub 组织或受控域名证明目标所有权 | Owner verified | “目标所有者提交/确认” |
| Independently reproduced | 至少两个彼此独立的 submitter/operator identity，使用不同 runner instance 重现同一 subject 的同一 observation class；目标 subject 本身保持相同 | Independently reproduced | “独立重现” |
| Project-operated-run | 由本项目运营的受控 runner 对已验证目标运行 | Project-operated runner | “由本项目 runner 观测” |

这些是来源可信度，而非产品质量等级。任何等级都可能 fail；Owner verified 也不高于 independently reproduced。

### 19.5 新鲜度与可比性

- Hosted endpoint 默认 30 天后标为 stale；自托管不可变 artifact 以版本为新鲜度边界；
- pack 或 profile digest 不同的结果不得直接计算趋势差，UI 只能并排比较；
- 版本趋势只在相同 scenario denominator 上计算；
- rolling/latest 标签是可变指针，页面必须同时显示实际 observation digest；
- 已知服务端静默更新时，subject 增加 observed fingerprint，并降低“同版本可比”置信度；
- Registry 每日重算 stale、撤销签名、已知受影响 runner 和 pack supersession 状态。

### 19.6 提交与验证流水线

~~~mermaid
flowchart TD
    A["本地运行并脱敏"] --> B["生成规范化 observation"]
    B --> C["签名与 provenance attestation"]
    C --> D["Registry schema / secret / policy 检查"]
    D --> E["重放确定性 oracle"]
    E --> F["存储不可变 artifact"]
    F --> G["发布带信任与新鲜度标签的页面"]
    D --> H["隔离或拒绝"]
    E --> H
~~~

Ingest 必须执行：

1. JSON Schema 与 canonicalization 校验；
2. pack/profile/driver digest 是否存在且签名有效；
3. 文件类型、大小、压缩比、路径与总 artifact 配额校验；
4. secret、token、Authorization、Cookie、URL query 与高概率 PII 扫描；
5. 使用 observation 固定的 oracle_digest、pack_digest、profile_digest 和 core_digest 重算确定性 assertion；缺少对应 artifact 即拒绝可信发布；
6. runner 与签名身份、时间、OIDC claim、artifact digest 绑定校验；
7. 重复提交折叠，但保留独立 provenance；
8. 可疑结果进入 quarantine，不公开原始数据。

推荐 attestation 使用 in-toto statement；工作期 predicate type 使用 urn:agentapi-doctor:attestation:run:v1，P00 名称与域名锁定后再迁移到最终 HTTPS namespace，且 P07 发布前不得再变化。JSON 签名输入按 [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785) 规范化，密钥与无密钥签名采用 [Sigstore](https://docs.sigstore.dev/)，构建 provenance 对齐 [SLSA](https://slsa.dev/)。

新 oracle 发现旧判定错误时，不覆盖原 observation。Registry 生成 DerivedEvaluation，记录 parent_observation_id、新 oracle/core digest、新 verdict、原因和时间；UI 同时展示 original、superseded interpretation 与 provenance。只有明确的 schema migration 可以产生新 observation representation，且保留双向映射。

### 19.7 存储与服务拓扑

| 数据 | 建议实现 | 原因 |
|---|---|---|
| observation 元数据、争议、身份 | PostgreSQL | 事务、筛选、约束 |
| report、wire、repro、attestation | OCI registry 或 S3-compatible object store | 内容寻址、大对象、生命周期 |
| pack、profile、driver artifact | OCI artifact | digest pinning 与签名 |
| 搜索 | PostgreSQL FTS 起步；需要时再引入专用搜索 | 降低运营复杂度 |
| 公共页面 | 静态增量构建加 CDN | 便宜、抗流量突发、降低攻击面 |
| 异步验证 | 有界队列与隔离 worker | 防止 ingest 阻塞、控制资源 |

控制面和测试执行面分离。Web API 永不直接执行用户提交的脚本；worker 只接受已签名的声明式 pack 与允许列表 driver。

### 19.8 Registry API

首个稳定 API：

~~~text
POST   /v1/observations:prepare
POST   /v1/observations:commit
GET    /v1/observations/{digest}
GET    /v1/observations?subject=&version=&pack=&profile=&trust=&fresh=
GET    /v1/subjects/{owner}/{project}
GET    /v1/packs/{name}/{version}
GET    /v1/profiles/{name}/{version}
POST   /v1/ownership/challenges
POST   /v1/disputes
GET    /v1/disputes/{id}
GET    /v1/badges/{subject}/{profile}.svg
~~~

Prepare 返回上传 URL、大小限制与 challenge；Commit 只接受 prepare manifest 中的 digest。列表端点使用 cursor pagination、ETag、明确的速率限制。所有 schema 在仓库中生成 OpenAPI 文档和客户端。

### 19.9 公共 runner 与 SSRF 边界

公共 runner 不接受任意 endpoint：

- 先验证项目/域名所有权，再显式加入目标 allowlist；
- 解析域名后拒绝 loopback、private、link-local、multicast、保留地址与云 metadata 地址；
- 每次 redirect 和连接都重新解析并校验，防止 DNS rebinding；
- 固定 outbound proxy、协议、端口、总流量、响应大小、并发与持续时间；
- 禁止 file、gopher、自定义 scheme、Unix socket 与用户提供代理；
- 测试账户必须是最小权限、专用、可撤销、带预算；
- 默认只调用声明为无副作用的合成模型/测试部署；真实付费模型需要所有者明确启用。

### 19.10 抗刷榜与争议

- project-operated runner 对等价 scenario 做动态变形：随机 tool 名、call ID、字段顺序、合法 chunk 边界与无害未知字段；
- 不公开下一轮全部随机种子；发布后将种子和结果一起披露；
- 任何 Badge 都包含 pack/profile digest、新鲜度与信任标签；
- 同一组织重复运行不增加独立重现数量；
- 结果页展示配置和 skip 原因，禁止通过关闭困难 capability 提高百分比；
- 项目所有者可以提交说明和修复链接，但不能删除真实结果；
- 争议公开显示 opened、under review、resolved、superseded；安全或隐私事件可先隐藏敏感 artifact，保留审计记录；
- 至少一名非相关维护者复核争议；目标厂商不能单独批准自己的结论；
- 赞助关系在结果页披露，但不进入排序算法。

### 19.11 自托管

Registry 社区版使用 Docker Compose 一键启动，包含 API、worker、PostgreSQL、对象存储和静态 UI。Helm chart 在真实组织提出 Kubernetes 需求后提供。自托管版必须：

- 能离线导入 pack/profile/driver OCI bundle；
- 支持完全禁用公共提交与遥测；
- 支持企业自有 OIDC、retention 与 encryption key；
- 使用相同 observation schema 和验证器，避免形成私有分叉；
- 支持导出可验证 bundle，必要时再提交公共 Registry。

### 19.12 身份、授权与所有权生命周期

Registry OIDC/PAT scope：

| Scope | 能力 |
|---|---|
| observation:prepare | 为本人创建有配额的上传 session |
| observation:commit | commit 本人 prepare 的 exact digest |
| ownership:manage | 对已验证 subject 创建/更新 challenge |
| dispute:create | 创建争议和 owner response |
| runner:submit | project-operated runner 提交 attestation |
| moderation:review | quarantine、争议、撤敏审查，不含基础设施 admin |
| registry:admin | 极少数 break-glass 运维 |

Token 不放 query，只存 hash/issuer/subject/scopes/expiry；服务账户短期化并可逐个撤销。Prepare/Commit、ownership、moderation 和 admin 写操作全部有对象级授权与 audit event。

所有权不是永久的：

- DNS/GitHub/domain challenge 绑定 exact subject namespace 和 nonce；
- hosted endpoint 至少每 90 天重新验证，DNS/组织/domain 变更或 challenge 失败立即降级 trust；
- 域名转移、GitHub org rename/delete、签名撤销、账户 compromise 都可触发 ownership revocation；
- 旧 observation 的历史签名事实保留，但当前页面不得继续显示 owner-current；
- ownership transfer 需要新 owner 验证，旧 owner 不能删除历史失败；
- break-glass 操作双人批准并在 24 小时内复核。

### 19.13 Terms、撤敏与物理删除

Hosted Registry 上线前必须发布 REGISTRY_TERMS.md、PRIVACY.md、ACCEPTABLE_USE.md、DATA_LICENSE.md 和 takedown/security-embargo 流程。上传者必须声明：

- 有权提交和授权对应数据；
- 已取得所需 consent，且内容不含禁止的 secret/个人数据；
- artifact 的原始许可证/SPDX 与第三方来源；
- 是否明确同意将指定的非敏感事实投影加入 CC0 export；
- 接受公开不可变 metadata、争议和撤敏规则。

安全漏洞 finding 支持 coordinated disclosure embargo：原始 artifact、target details 和 public page 暂不公开，仅 Security Team/目标所有者可见；在修复或约定窗口后发布最小事实。普通厂商声誉争议不能滥用安全 embargo。

删除分两类：

1. Logical correction：非敏感事实不覆盖，通过 tombstone/supersede/dispute 追加；
2. Sensitive hard purge：secret、PII、违法内容或无权提交的 blob 从 object store、CDN、search、cache 和公开页面主动删除，保留不含敏感数据的随机事件 ID、时间、reason class 和受限 audit。

Active stores 的敏感 hard purge 目标 24 小时内完成；backup 使用独立 encryption key 和最长 30 天滚动过期，紧急时销毁对应 key。删除任务有可验证清单但不得把待删内容 hash 公开。Creative Commons 明确说明 CC licenses/CC0 不可撤回且应用者必须拥有或控制所需权利：[CC License Your Work](https://creativecommons.org/cc-license-your-work/)。服务可以停止继续分发并处理隐私请求，但不能保证第三方已复制的数据消失；上传 UI 必须在确认前明确提示这一点。

---

## 20. 安全、隐私与滥用防护

### 20.1 安全目标

1. 测试一个恶意 endpoint 不应导致 runner 被接管；
2. 恶意响应、pack、driver 或 report 不应在维护者/浏览者环境执行；
3. 密钥与对话内容在默认路径上不落盘、不上传；
4. 公共服务不能成为 SSRF、DDoS、免费代理或付费 API 消耗器；
5. 发布 artifact 可验证来源，依赖被篡改能够被检测；
6. 删除敏感公开数据时保留最少审计事实，而不继续分发数据本身。

### 20.2 威胁模型

| 威胁主体或故障 | 典型攻击 | 核心控制 |
|---|---|---|
| 恶意 endpoint | 无限 SSE、压缩炸弹、巨型 header、慢速响应、注入终端控制符 | 严格字节/时间/事件/解压上限，流式解析，字符转义 |
| 恶意模型输出 | prompt injection 要求 runner 调用危险工具 | 只注册 inert synthetic tools，不执行模型提供的命令 |
| 恶意 pack | 任意代码、读文件、出网、资源耗尽 | 默认纯声明 DSL、签名、审查；扩展代码隔离 |
| 恶意 driver | 窃取 env/key、读用户目录、持久化 | 子进程沙箱、显式 env allowlist、临时 HOME、资源与网络策略 |
| 恶意上传者 | SSRF、XSS、路径穿越、archive bomb、伪造结果 | ownership、内容寻址、重新验证、CSP、严格解包 |
| 依赖或 CI 被攻破 | 恶意 release、泄露发布 token | 固定 SHA、最小权限、OIDC、双人发布、签名、SBOM |
| 维护者误操作 | 上传真实 trace、错误公开争议材料 | 本地先脱敏、两阶段提交、预览、撤回和事件流程 |
| 结果操纵 | 特制响应识别测试、选择性 skip | 动态等价 mutation、分母透明、独立重现 |

### 20.3 Runner 隔离

分三级执行：

- Level A：core engine 与声明式 oracle，在主 runner 进程运行；
- Level B：官方 driver 子进程，独立临时目录、临时 HOME、只读安装、CPU/内存/进程/文件描述符限制；
- Level C：第三方或实验 driver，仅允许在容器、Linux user namespace 或 microVM 中运行，公共 Registry 默认禁用。

Linux 优先使用 user namespace、seccomp 与 bubblewrap/容器；macOS 和 Windows 使用平台沙箱可用能力，否则把第三方 driver 明确标为 unsandboxed 并要求用户 opt in。无论平台：

- 环境变量使用 allowlist，不继承整个父进程环境；
- secret 通过一次性文件描述符或 stdin 注入，不作为命令行参数；
- driver 工作目录不得是被测 repo 或用户 HOME；
- 禁止符号链接逃逸和绝对路径 artifact；
- stdout/stderr 按字节限制并转义控制字符；
- 超时后先优雅终止，再终止整个进程组；
- 不允许 driver 自行决定上传内容。

### 20.4 网络与请求安全

默认上限建议：

| 项 | 默认值 | 是否可由本地用户调整 |
|---|---:|---|
| Response headers | 64 KiB | 是，公共 runner 不可超硬上限 |
| 单个 SSE event | 1 MiB | 是 |
| 单响应解压后 body | 64 MiB | 是 |
| 单 scenario wall time | 120 秒 | 是 |
| Streaming idle | 30 秒 | 是 |
| Redirect | 0；显式启用最多 3 | 是 |
| 单 scenario 请求数 | 8 | 是 |
| 单运行 artifact | 512 MiB | 是 |

实际硬上限由安全评审后确定并集中定义，不散落在 adapter。Content-Encoding 必须限制解压比例和嵌套；TLS 校验默认开启，insecure 仅限本地并在报告中高亮。代理配置不得自动读取未知 repo 中的环境文件。

重试规则：

- 在尚未发送 request body 或服务端提供可靠 idempotency key 时，才能自动重试安全的网络建立失败；
- 收到任何响应字节后不透明重试 streaming；
- 429/5xx 默认记录而非隐藏，用户可选择单独的 resilience policy；
- 重试次数、原因、退避和最终 evidence 全部进入报告。

### 20.5 Secret 与隐私

Redaction pipeline 必须在写盘前执行：

1. 按字段名删除 Authorization、Proxy-Authorization、Cookie、Set-Cookie、api-key 与已注册 provider key；
2. 删除 URL userinfo 和 query secret，保留 host/path 的可配置哈希；
3. 使用用户提供的 literal secret set 做最长匹配替换；
4. 检测常见 token 前缀、JWT、PEM、云凭据和高熵字符串；
5. 对 prompt、completion、tool arguments 默认只保留结构和长度；需要相等性比较时用本地 keyed HMAC，低熵或敏感内容不保存普通 hash；
6. 再对准备上传的 bundle 做独立 secret scan。

数据模式：

| 模式 | 本地保存 | 可上传 |
|---|---|---|
| strict，默认 | 结构化摘要、失败附近已脱敏 wire、hash | 最小失败证据 |
| debug | 完整本地 trace，加密并设过期时间 | Public hosted Registry 永久拒绝 |
| synthetic | 完整合成输入和 trace，仍需扫描模型输出 | 扫描通过后允许 |
| metadata-only | 状态、耗时、计数、digest | 允许 |

synthetic 输入不代表模型输出天然无 PII、版权或不安全文本；上传前仍经过相同 content/secret scanner 和 policy。

debug/full_local_encrypted 的 v1 安全边界：

- 每个 Run 生成独立 data-encryption key，使用成熟 AEAD；具体算法与库由安全 ADR 锁定；
- key 只能由 OS keyring、用户明确提供的 KMS/age recipient 或权限合格的 key file 包装；无可用 key provider 时拒绝 full 模式，不能回退明文；
- artifact 只保存 wrapped key metadata，不保存解密 secret；CLI 参数和日志不得出现 key；
- 默认 24 小时过期，删除 wrapped key 实现 crypto-erasure；轮换只 re-wrap data key；
- backup 默认排除 debug blob 和本地 key；若用户显式备份，报告 retention 风险；
- decrypt/export 每次需要显式命令并产生本地 audit event；Public hosted Registry 永久拒绝 debug/full_local_encrypted class，不能用确认 flag 覆盖；
- 对低熵 payload/secret 不保存普通 hash，使用本地 keyed HMAC 或只保存长度/类型。

若用户要分享 debug 中的 finding，必须在本地执行 export-redacted 生成新的 redacted_content artifact，重新扫描、计算新 digest 并单独签名；不能把原 debug artifact 改标签。Self-hosted Registry 是否接收 debug 由其本地管理员政策决定，但 UI 必须显示高风险且默认关闭。

不做默认遥测。若未来增加 opt-in telemetry，必须单独 RFC，列出字段、用途、retention、删除方式和 self-host disable；不得上传 base URL、模型内容或密钥。

### 20.6 Pack、Driver 与供应链

- 官方 pack 只能使用声明式 DSL；需要新 oracle 能力时先扩展受审 core primitive；
- 实验自定义 oracle 可使用 WASM capability sandbox，但不能在 v1.0 stable pack 中成为必要依赖；
- Registry 只运行签名并在 allowlist 中的 driver digest；
- GitHub Actions 固定到完整 commit SHA，Dependabot/Renovate PR 仍需测试；
- 发布生成 CycloneDX 或 SPDX SBOM、provenance、checksums 与 Sigstore bundle；
- release、pack、profile、driver 分别签名，不能因为 runner 可信就跳过 pack 验证；
- maintainer 强制 2FA，发布身份使用短期 OIDC，不保存长期云密钥；
- fork PR 不接触 secret，不使用带写权限的 pull_request_target 执行 fork 内容；
- 每季度恢复演练：从 tag、provenance 和干净环境重建并核对 digest。

### 20.7 Report 与 Web 安全

- 所有响应文本按数据渲染，禁止 raw HTML；
- 使用严格 Content-Security-Policy，不加载未知第三方脚本；
- 下载 artifact 设置 attachment、nosniff 与独立域名；
- 解包拒绝绝对路径、父目录、设备文件、符号链接、过多文件和异常压缩比；
- terminal output 清除 ANSI/OSC 控制序列，CLI 提供安全纯文本模式；
- Markdown 链接 scheme allowlist；外链标记，不内嵌远端图像；
- 公共错误页不返回 stack、SQL、内部路径或 secret；
- 所有管理操作有不可变 audit log。

### 20.8 漏洞披露与安全响应

仓库发布 SECURITY.md：

- 私密报告渠道与可选加密方式；
- 3 个工作日内确认，7 个工作日内完成初步分级；
- 默认协调披露窗口最长 90 天，正在利用的高危问题走紧急流程；
- 受影响版本、临时缓解、修复版本与公告格式；
- CVE/GHSA 申请责任人；
- secret exposure、恶意 artifact、Registry compromise、错误公开私有 trace 四类 runbook；
- 事件结束后发布不泄露敏感细节的复盘。

v1.0 前安排一次独立安全设计评审和一次 Registry 渗透测试；所有高危问题关闭，中危问题有明确 owner 和期限。

---

## 21. 非功能需求、性能与运营

### 21.1 可复现性与确定性

- 同一 evidence bundle、同一 oracle/pack digest 必须产生逐字节一致的 scenario verdict JSON；
- 人类可读 HTML 中的生成时间等非确定字段与 verdict 分离；
- scenario 顺序稳定，随机 mutation 使用记录在 manifest 的 seed；
- 所有时间比较由虚拟时钟或容忍窗口 assertion 完成，不依赖墙钟巧合；
- hash、canonical JSON、排序和浮点表示跨平台一致；
- reference fixture 在 Linux、macOS、Windows 的 golden 输出一致。

不变量：对同一合法 evidence、oracle/core/pack digest 的 deterministic verdict JSON，独立重算必须 100% 逐字节一致；任何不一致都是 defect，不用统计阈值豁免。重新向相同不可变本地部署发请求的整次重跑允许受环境影响，目标一致率不低于 95%。二者必须分开统计。

### 21.2 运行模型与调度

- 单 scenario 内的步骤默认串行，除非 DSL 明确声明 concurrency；
- scenario 之间按 target token bucket 并行；
- 默认提供 conservative、normal、aggressive 三档并发，不把模型并发极限当兼容性；
- 按 endpoint、credential、model 三个 key 共同限流；
- scheduler 支持 request、token、cost、wall-clock、response/artifact bytes、process/disk 预算；
- hard-enforceable：新请求发出前的 request count、proxy response/egress bytes、artifact/disk、进程数、deadline 后终止；这些不得超限，除已记录的进程终止 grace；
- advisory/reservation-based：provider token/cost，因为 usage 可能延迟返回、模型可能不严格服从 max token、SDK retry 可能只在 client observation 后可见；发请求前按最坏估算 reservation，超过剩余预算不启动；
- token/cost 最坏 overshoot 上限是已启动 in-flight requests 的 reservation 总和；报告 requested limit、reserved、provider-reported actual、unknown usage 和 overshoot，不能承诺绝对零超支；
- 预算耗尽使用 execution_status=skipped、reason_code=budget_exhausted，不伪装成 endpoint failure；
- Ctrl-C 第一次停止调度并完成写盘，第二次强制终止；
- 中断后可 resume 已完成的确定性 scenario；进行中的 scenario 从头运行并产生新 attempt。

### 21.3 性能预算

该项目不是压测器，性能指标均为诊断信息，不参与默认兼容性 pass/fail。仍设工程预算：

| 场景 | 目标 |
|---|---|
| CLI cold start | 常见开发机小于 500 ms，未加载 SDK driver |
| 10,000-event fixture replay | p95 小于 2 秒 |
| 100 MiB wire trace 转换 | 峰值内存小于 256 MiB，采用流式处理 |
| HTML report 生成，1,000 scenarios | 小于 10 秒 |
| Registry metadata API | 缓存命中 p95 小于 250 ms |
| Registry ingest | 99% 在 5 分钟内验证完成，不含等待公共 runner |

这些是初始 SLO，先通过 benchmark 固化基线再作为阻断门槛。性能回退超过 20% 且无解释时阻断发布。

### 21.4 预设 Suite 预算

| Suite | 目标时长 | 默认请求上限 | 用途 |
|---|---:|---:|---|
| smoke | 2 分钟 | 15 | 安装、PR 快速检查 |
| core | 15 分钟 | 80 | 基础 protocol conformance |
| client profile | 每 profile 20 分钟 | 120 | SDK/agent 真实路径 |
| exhaustive | 用户设预算 | 不设低默认值 | 夜间、发布前 |
| registry verify | 由项目策略限定 | 固定配额 | 公共可信结果 |

实际时长依赖 endpoint；超时报告必须区分 runner、排队、网络和生成阶段。成本只从 provider 返回 usage 与用户配置价格估算，核心仓库不内置易过期的价格表。

### 21.5 Artifact 生命周期

- 解析 streaming 时边读边写到 content-addressed chunks，不把完整 body 留在内存；
- 相同 fixture/chunk 去重；大 artifact 使用 zstd，但签名对象是解压后规范内容的 digest 与压缩 manifest；
- 本地默认保留最近 20 次或 30 天，由用户配置；
- public-minimal 长期保留 verdict、manifest、最小失败 fixture；大 raw trace 短期保留或不上传；
- deletion 分为隐藏敏感 blob 与保留不可逆摘要/审计事实；
- 定期验证对象引用、digest、备份恢复和孤儿清理。

### 21.6 可观测性

Core 使用结构化日志并提供 OpenTelemetry opt-in exporter。关键 span：

- run.plan、scenario.execute、http.request、stream.consume；
- driver.spawn、driver.observe、oracle.evaluate、minimize.attempt；
- registry.prepare、registry.verify、registry.publish。

关键 metrics：

- scenario 状态与 failure class；
- 请求/响应字节、SSE 事件、TTFT、inter-event gap、总时长；
- driver crash/timeout、minimizer reduction ratio；
- Registry queue latency、verification failure、secret quarantine；
- pack drift、新鲜 observation 比例、独立重现率。

本地日志默认不包含 payload。Trace ID 写入 artifact，允许从人类报告定位到 wire evidence，但公共页面显示的是随机 observation-scoped ID。

### 21.7 可靠性与灾难恢复

Registry 初始目标：

- metadata/read API 月可用性 99.9%；
- ingest 月可用性 99.5%，失败可安全重试；
- RPO 24 小时、RTO 8 小时，进入 v1.0 前通过恢复演练；
- DB 每日备份、对象存储版本化、签名 key 不与数据同域；
- 队列至少一次投递，worker 操作按 observation digest 幂等；
- 发布页面从不可变数据库快照构建，可在控制面故障时继续只读。

99.9% read SLO 仍计入灾难；8 小时 RTO 是最坏恢复目标，不是可排除的计划停机。若一次灾难恢复超过月 error budget，必须记录 SLO miss、冻结非可靠性功能并复盘；静态 CDN snapshot 是降低 read outage 的主要手段。

按当前项目章程，公共 Registry/Matrix 是 v1.0 差异化核心，不能一边满足 GA_READY 一边把 hosted Registry 标为 beta。若没有足够维护者承担 hosted 服务，项目状态保持 BLOCKED，或通过范围 RFC 修改章程、DoD 和对外定位后再重新评估；本地 CLI 不得依赖 Registry 可用性。

---

## 22. 质量工程、CI/CD 与发布

### 22.1 测试组合

| 层 | 内容 | PR 是否阻断 |
|---|---|---|
| Unit | parser、FSM、canonicalization、redaction、oracle、budget | 是 |
| Golden | wire → IR → verdict → report 的跨平台 fixture | 是 |
| Property | event 分块、字段顺序、ID、JSON fragment、未知事件 | 是，有限 seed |
| Fuzz | parser、SSE、JSON、archive、redactor、minimizer | corpus 回归阻断；长 fuzz 夜间 |
| Contract | Driver RPC、Pack schema、Registry API、CLI JSON | 是 |
| Reference | pack-conforming reference server 的合法行为全部通过 | 是 |
| Mutation | 每个关键 assertion 至少杀死一个定向 mutant | 是 |
| SDK matrix | support-manifest 锁定的 previous/current 两个 Tier 1 版本；candidate 非阻断 | Tier 1 cells 阻断，candidate/扩展夜间 |
| Historical | 公开 bug corpus 仍被正确识别与归因 | 是 |
| Provider canary | 真实托管 API 的漂移监控 | 否，单独告警和人工确认 |
| Registry security/load | SSRF、上传、鉴权、限流、恢复 | main/nightly/release 分层 |

所有新 assertion 的合并条件：

1. Requirement Catalog 中有来源与解释；
2. reference fixture 通过；
3. 至少一个最小 mutant 被杀死；
4. 失败信息能定位到 evidence；
5. 不稳定生成内容不参与确定性断言；
6. 若修复历史 bug，关联上游 issue 与 affected/fixed version。

### 22.2 Flaky 管理

- 不以自动 retry 把 flaky 变绿；
- 检测到不稳定时标记 quarantined，记录 owner、原因、首次日期和移除期限；
- quarantined scenario 不进入兼容性分母，但在报告中显眼显示；
- 超过 14 天未修复自动升级为 release blocker 或删除错误断言；
- provider canary 连续三次同指纹变化后创建 drift issue，但规范变更仍需人工核验；
- 维护 flaky rate 仪表板，核心 deterministic suite 目标低于 0.1%。

### 22.3 CI Workflows

每个 PR：

- format、lint、schema/requirement link 检查；
- unit、golden、reference、mutation smoke、historical corpus；
- Go race test、staticcheck、govulncheck、golangci-lint；
- driver contract 与 Python/Node driver unit；
- Linux/macOS/Windows，amd64；arm64 至少 build；
- secret、license、dependency、CodeQL 扫描；
- 文档链接、示例命令和 generated schema drift 检查；
- 不调用真实付费 provider，不读取仓库 secret。

Nightly：

- 扩展 SDK/client matrix；
- 长时间 fuzz 与全 mutant suite；
- pack-conforming reference server 跨架构；
- 允许列表 provider canary，用专用低预算账户；
- public Registry stale/attestation/object integrity 检查；
- benchmark 与 size regression。

Release candidate：

- 全平台 clean-environment install；
- offline、proxy、TLS、自托管 Registry smoke；
- upgrade/downgrade 与旧 report 读取；
- SBOM、provenance、签名验证；
- 安全测试、恢复演练状态、文档版本切换；
- 至少两名维护者在不同环境复现 release checklist。

### 22.4 分支与合并策略

- trunk-based development，main 始终可发布；
- feature branch 短生命周期，较大设计用 RFC 后拆小 PR；
- 必需检查、CODEOWNERS、至少两人批准关键 schema/security/release 变更；
- 禁止 force push main，启用线性历史或 merge queue；
- generated 文件由 CI 验证，不接受未说明的大规模重生成；
- release branch 仅用于稳定期修复，修复先进入 main 再 backport；
- security fix 可走私有 fork，发布后补齐公开历史。

### 22.5 版本与兼容承诺

独立版本面：

| 对象 | 版本策略 | 稳定性承诺 |
|---|---|---|
| CLI/Core | SemVer | v1 后 breaking 只在 major |
| Result/Observation schema | 显式 schema version | v1.0 读取全部已发布稳定 v1 schema；v2 起读取当前与前一稳定 major，或提供离线 migration |
| Pack | CalVer YYYY.MM.patch；protocolRevision 独立字段；OCI digest 固定 | 已发布 digest 永不变，禁止把其他版本轴塞进 build metadata |
| Profile | SemVer | capability/denominator 变化至少 minor |
| Driver RPC | 协议 SemVer + capability negotiation | 支持当前与前一 minor |
| Registry API | URL major | 同 major additive-first |
| Requirement Catalog | source revision + digest | 旧 revision 可追溯 |

Breaking 的判定包含：字段删除/改义、默认隐私下降、退出码变化、scenario denominator 静默变化、旧 artifact 无法读取。新增 optional 字段、未知事件透传和新 protocol pack 通常是 minor，但必须测试旧 reader。

首个稳定 major 没有虚构的“前一 major”。P01 必须生成 `schemas/migration-floor.yaml`：它列出要长期读取/迁移的明确 pre-1.0 candidate schema ID、version、digest 与 fixtures；若没有任何被公开承诺的 0.x artifact，则该列表可以为空，v1.0 只承诺全部已发布稳定 v1 schema。previous-major 兼容 gate 从 v2.0 开始，固定 v1 最后稳定 schema corpus，不能用任意开发期 v0 文件充数。

弃用流程：

1. 发布 deprecation RFC/issue、替代方案与迁移工具；
2. 至少跨两个 minor 并维持 90 天；
3. CLI 每次使用给一次可抑制告警，JSON 输出给 machine-readable warning；
4. 下一 major 才删除；
5. Registry 保留旧 schema reader 或提供离线转换器。

### 22.6 发布物

每个 stable/RC release：

- Linux、macOS、Windows 的 amd64/arm64 静态或自包含 CLI；
- OCI image，非 root、最小 base、固定 digest；
- Homebrew、Scoop；WinGet 在自动更新可靠后加入；
- checksums、SPDX/CycloneDX SBOM、SLSA provenance、Sigstore signature；
- 对应 pack/profile/driver OCI artifact 与 source archive；
- changelog、breaking/migration、known issues、支持期限；
- 可验证的一行安装方式，但文档同时给手动 signature 校验。

不覆盖已发布 tag/artifact；发现发布错误只能 yank 指针并发布新 patch。Stable 目标每 6–8 周，RC 两周，nightly 不承诺兼容。支持当前 minor 和前一 minor；每个 major 的最后一个 minor提供 12 个月安全修复窗口，资源不足时提前公开调整而非默默停止。

### 22.7 发布权限

- 发布由 GitHub Environment 保护，需要两名 maintainer 批准；
- CI 使用 OIDC 获取短期签名与 registry 权限；
- release workflow 输入只允许已经保护的 tag；
- 一名 Release Manager 执行，一名不同组织的 verifier 核验；
- 发布后自动从公开下载地址安装、验签、跑 smoke；
- 失败时停止推广渠道，不删除审计证据。

---

## 23. 治理、法律、文档与贡献者体验

### 23.1 License 与知识产权

- 代码、pack、schema、示例默认 Apache-2.0；
- 文档使用 Apache-2.0，若社区更需要内容复用可单独采用 CC-BY-4.0；
- 公共 observation 只把 DATA_LICENSE.md 定义的、权利清楚且上传者明确同意的非敏感事实投影纳入 CC0 export；身份、签名、评论、模型文本和原始 artifact 不自动 CC0；
- 上传者保留原始 artifact 权利，并按 REGISTRY_TERMS 授予托管、复制、验证、生成脱敏派生物和公开展示所需的非独占许可；
- Developer Certificate of Origin 只覆盖进入源码仓库的贡献，不覆盖 Registry 上传；Registry 使用单独的 upload attestation/terms；
- fixture 优先自行构造，每项保存 SPDX、来源、作者和允许用途；不复制带不明许可的 SDK test、Issue 内容或用户日志；
- 引用规范只存 requirement 摘要、短摘录和链接，不镜像整份受版权保护文档；
- TRADEMARKS.md 说明名称、logo、徽章的允许用法；
- 正式定名前做 GitHub、包管理器、域名和商标检索。由于已有 [coder/agentapi](https://github.com/coder/agentapi)，不得把 agentapi 作为含糊 CLI/package 名直接发布。

建议将 agentapi-doctor 视为工作名。第 0 阶段给出 3 个经过检索的候选名，并在代码、Go module、OCI namespace、域名上统一。

上述是工程设计，不是法律意见。Hosted Registry 上线前由适用司法辖区的律师复核 License、Terms、Privacy、CC0 export、商标、takedown 与跨境/未成年人问题；法律 review 是 P07 EXTERNAL evidence。

### 23.2 必备社区文件

~~~text
README.md
LICENSE
NOTICE
CONTRIBUTING.md
CODE_OF_CONDUCT.md
SECURITY.md
GOVERNANCE.md
MAINTAINERS.md
ROADMAP.md
SUPPORT.md
RELEASE.md
DATA_POLICY.md
DATA_LICENSE.md
REGISTRY_TERMS.md
PRIVACY.md
ACCEPTABLE_USE.md
TRADEMARKS.md
ADOPTERS.md
CODEOWNERS
rfcs/
adrs/
.github/ISSUE_TEMPLATE/
.github/PULL_REQUEST_TEMPLATE.md
~~~

README 开头只回答：痛点、与现有 tester 的差异、60 秒运行、真实 failure report、支持范围与安全提示。不要先展示星标、赞助或宏大愿景。

### 23.3 角色

| 角色 | 权限与责任 | 晋升条件 |
|---|---|---|
| Contributor | issue、fixture、文档、代码 | 遵守贡献流程 |
| Reviewer | 对熟悉目录 review | 持续高质量贡献与维护者提名 |
| Pack Maintainer | requirement、scenario、upstream drift | 协议知识、来源严谨、无未披露利益冲突 |
| Driver Maintainer | SDK/client matrix、release compatibility | 对应生态经验和稳定维护 |
| Core Maintainer | merge core、release 候选批准 | 跨模块贡献、可靠响应、社区信任 |
| Registry Operator | 生产运维、隐私与争议执行 | 安全训练、最小权限、审计 |
| Security Team | 私密漏洞、事件响应 | TSC 指派，身份可公开或私密 |
| TSC | 范围、治理、预算、重大 RFC | 公开选举/任命规则 |

晋升、休眠、恢复、移除均写入 GOVERNANCE.md。权限每季度复核；不活跃 6 个月先联系再降权。紧急安全权限不自动授予所有 maintainer。

### 23.4 决策机制

必须 RFC 的变更：

- result/observation schema 与 scoring；
- 新 protocol family 或 normative tier；
- Registry trust、隐私、数据 retention；
- plugin/driver ABI；
- breaking CLI/config；
- telemetry；
- 治理、license、商标和赞助政策。

RFC 至少开放评论 14 天；两名 maintainer 批准，其中一名来自非作者组织。安全紧急修复可先实施，7 天内补 ADR/RFC。实现细节使用 ADR，记录 context、decision、alternatives、consequences。

Bootstrap Charter 避免新项目治理死锁：

- P00 时作者是临时 Bootstrap Maintainer，只能把 RFC 标为 provisional，不能自称 TSC；
- 基础 RFC 公开评论至少 14 天，并向至少两个独立上游/专家发出 review 邀请；normative/security/schema RFC 至少获得一名外部实质 review 才能作为 P01 contract freeze 输入；
- 若无人 review，可合并 draft 供实验，但 P01 aggregate gate 保持 WAITING_EXTERNAL，不能把作者自审当批准；
- Bootstrap Maintainer 不能发布 stable badge、裁决自己的 Registry 争议或绕过安全 gate；
- 达到 3 名可发布 maintainer、来自 3 个独立组织/雇主，且 Core/Pack/Security 职责有人承担后，按公开程序成立 TSC；
- TSC 成立后重新 ratify 所有 provisional RFC，Bootstrap Charter 自动失效。

避免 vendor capture：

- 同一雇主不得占 TSC 超过三分之一；
- 厂商不能单独批准自己的 profile、结果争议或例外；
- pack 的 normative 变更至少两方审批；
- 赞助方不获得测试豁免、排序、Roadmap 否决权或私有 passing badge；
- 所有利益冲突在 PR/RFC 中披露。

### 23.5 贡献最小单元

让不熟悉整个架构的人也能贡献：

- 一份公开 bug 的最小 redacted fixture；
- 一个 requirement source revision；
- 一个 assertion + reference pass + mutant fail；
- 一个 SDK/client driver 版本更新；
- 一个 protocol profile；
- 一个错误信息或文档修复；
- 一个已验证 compatibility observation；
- 一个 upstream issue/PR 的回链。

提供 `doctor dev scaffold <requirement|scenario|fixture|profile|driver> <name> --output <directory>` 命令生成对应 skeleton、requirement link、golden 与 PR checklist。CI 失败必须给出本地复现命令。

### 23.6 文档信息架构

~~~text
docs/
  getting-started/
  concepts/
    compatibility-layers
    evidence-and-oracles
    profiles-and-packs
  protocols/
    openai-chat
    openai-responses
    anthropic-messages
    google
    mcp
  clients/
  authoring-packs/
  authoring-drivers/
  registry/
  security-and-privacy/
  operations/
  migration/
  reference/
  contributing/
~~~

英文是规范主文档，中文提供完整 Getting Started、架构、贡献指南与常见协议。翻译标明对应 commit，避免中文成为过期副本。文档包含：

- 可复制但不含真实 key 的命令；
- pass、fail、inconclusive、skip 示例；
- 如何解读 wire/model/client/task 分层；
- 如何提交最小 repro 给上游；
- 离线、代理、企业 CA、自托管；
- 数据上传前预览与删除；
- 从旧 schema/config 的迁移。

CLI、Web 与文档满足基本可访问性：不只依赖颜色、键盘可用、对比度合格、表格有文本替代、Badge 有可读 label。

### 23.7 支持与社区节奏

- GitHub Discussions：问答、设计与生态展示；
- Issues：确认的 bug、feature、spec drift；
- Security 渠道：漏洞与敏感数据；
- 每月公开维护者会议和简短纪要；
- 每季度发布 ecosystem compatibility drift 报告；
- SUPPORT.md 明确 best-effort、支持版本与响应预期；
- 不开设无法维护的 Slack/Discord；达到持续需求后再增加同步渠道。

项目申请 OpenSSF Best Practices badge，并逐步对齐 OpenSSF/OSPS 基线。治理成熟后评估加入中立基金会，但不把基金会迁移作为 v1.0 前置条件。

---

## 24. 交付路线图与阶段门禁

### 24.1 原则

这是 v1.0 成熟项目路线，不把能跑一条请求的 prototype 包装成产品。开发过程中仍会有 alpha、beta、RC 标签，用于诚实表达稳定性；任何阶段都不能降低安全、证据和规范可追溯的底线。

Roadmap 以 exit gate 而非日期驱动。时间是单人配合 Codex 的估算；有 2–3 名稳定维护者可并行压缩，但不能跳过独立复核、真实集成和观察窗口。

### 24.2 阶段总览

| 阶段 | 预计时间 | 主要结果 | 强制 Exit Gate |
|---|---|---|---|
| 0. 需求与差异化验证 | 第 0–8 周 | 竞品协作决策、名字、30 个故障 corpus、source catalog、核心 RFC | 能重现至少 20 个样本中的 16 个；至少 3 名外部上游维护者愿意评审/试用；证明能在 10 个失败中区分至少两类故障域 |
| 1. Conformance Kernel | 第 2–6 月 | Engine、DSL、Recorder、Oracle、reference/mutant、Chat + Responses + Anthropic、kernel 级 terminal/stable JSON 本地结果 | 150+ scenarios；pack-conforming reference 100% pass；50 targeted mutants 全部被杀死；10 个历史 bug 回归；跨平台 golden 一致 |
| 2. Client-observed Lab | 第 6–10 月 | Python/Node SDK、Codex、Vercel AI SDK、LiteLLM/OpenClaw profiles、Anthropic、最小化/归因 | §6.1 全部 Tier 1 cells：至少 8 个 driver identity、7 个 SDK/Agent profile、5 个 runtime adapter；5 个上游仓库试用；15 个问题被上游确认；false positive 低于 3% |
| 3. 可信 Registry | 第 10–16 月 | Tier 2 协议扩展、签名 observation、ownership、trust/freshness、争议、self-host、公共 Matrix | 第 6.2 节 required Tier 2 set 收敛；20+ 版本/配置组合；90% observation 新鲜；独立重跑一致率至少 95%；完成安全评审、恢复演练与隐私审计 |
| 4. v1.0 RC 与 GA | 第 16–22 月 | 稳定 contract、完整文档/治理/发布链、生态集成 | 第 30 节全部 DoD；RC 观察至少 6 周；无开放高危；5 个上游 CI adopter；至少 3 名 maintainer、来自 3 个独立组织/雇主 |
| 5. 成熟运营 | GA 后 | pack 漂移、更多 provider/client、研究 corpus、基金会评估 | 每季度按 Adoption、质量和维护容量重新排优先级 |

日历上的 research/spike 可在隔离 worktree 提前进行，但权威 Goal state 一次只有一个 active Phase/Work Unit，merge 和 aggregate gate 按依赖串行。Registry 可以在早期做不进入收敛证据的内部原型，却必须在 P06 完成后激活 P07，并完成安全与信任门禁后才能给公共可信标签。

### 24.3 阶段 0：需求与差异化验证

交付：

- 联系 am-i-openai-compatible、octest、FauxpenAI-conformance、Open Responses 维护者；
- 写 COMPETITIVE-LANDSCAPE.md：重叠能力、可复用标准、合作/合并可能、独立存在理由；
- 完成名称、module、package、OCI namespace、域名与商标初筛；
- 从一手上游 issue 建立至少 30 个候选，人工重现 20 个；
- 对每个样本标注 protocol、client、runtime、model、symptom、ground truth、可否合成；
- RFC-0001 compatibility layers；
- RFC-0002 evidence/result schema；
- RFC-0003 scenario/pack model；
- RFC-0004 driver isolation；
- RFC-0005 Registry trust；
- Threat Model v1 和 Data Policy v1；
- 用风险退休代码验证：SSE raw capture、Responses FSM、多工具 delta、SDK forward proxy。

风险退休代码不得成为绕过设计审查的隐藏生产架构；验证后要么转成有测试的正式组件，要么删除。

Exit review：

- 如果只有字段探活能够稳定重现，而 client-observed/归因没有新增价值，停止独立建仓并向现有 tester 贡献；
- 如果直接竞品愿意采用全部关键方向且治理可信，优先合并力量；
- 如果无法合法构建 corpus 或无法在写盘前可靠脱敏，不进入公共 Registry 路线；
- 将 go/no-go 会议纪要公开。

### 24.4 阶段 1：Conformance Kernel

实施顺序：

1. stable schemas 与 canonical artifact；
2. planner/budget/capability；
3. HTTP/SSE recorder 与 redaction；
4. raw event、IR、state machine；
5. oracle primitives 与 CEL；
6. pack-conforming reference server 与 mutant server；
7. OpenAI Chat pack；
8. OpenAI Responses HTTP pack；
9. Anthropic Messages pack；
10. kernel 级 terminal/stable JSON 本地结果；JUnit/SARIF/Markdown/offline HTML 在 Stage 2/P05 从同一 result model 产品化；
11. local replay；baseline/minimizer 在 Stage 2/P05 产品化。

阶段发布 pre-1.0 alpha，仅供 fixture author 和上游早期试用。公开文档明确：schema/CLI 仍可能变，结果不得作为认证 Badge。

Exit evidence：

- 150+ normative/high-value scenarios，至少 60 个 Responses；
- 每个 MUST assertion 都关联来源、reference pass、mutant fail；
- parser fuzz 累计 1 亿次无未解决 crash，或按 CPU-hour 等价门槛记录；
- 10 个历史 bug fixture 能给出正确 failure class 和 evidence pointer；
- smoke/core suite 符合性能预算；
- Linux/macOS/Windows clean install；
- strict 模式 artifact 通过 secret scan。

### 24.5 阶段 2：Client-observed Lab

交付：

- Python OpenAI SDK、Node OpenAI SDK 与 raw Go driver；
- Codex Responses profile，不提供伪 Chat fallback；
- Vercel AI SDK Responses/compatible ConsumerCompatibilityProfiles；
- LiteLLM proxy profile、OpenClaw 的 OpenAI/Anthropic core profiles；native Ollama 在 P06 Tier 2；
- Anthropic Messages 的 Python/Node SDK drivers；
- client observation 与 capture-layer evidence 自动相关；
- controlled backend、client differential、stream/non-stream metamorphic；
- failure attribution confidence、minimizer、Issue Bundle；
- GitHub Action、reusable workflow、SARIF/JUnit；
- baseline gate 和 upgrade matrix。

Exit evidence：

- 至少 5 个不同上游 repo/nightly 实际接入，不只是在本仓库演示；
- 至少 15 个 findings 被上游维护者确认，其中至少 5 个合并了修复或 regression test；
- 对有 ground truth 的验证集，错误归因 false positive 小于 3%，unknown 可以存在但不能硬猜；
- 最小化后 request/trace 中位缩减至少 50%，且 90% 仍保留 failure fingerprint；
- §6.1 的 8 个 Tier 1 driver identity 及其 support-lock matrix 自动运行；
- 外部使用者能在 30 分钟内从失败生成可提交 issue bundle。

### 24.6 阶段 3：可信 Registry

交付：

- observation/attestation schema v1 candidate；
- Sigstore/in-toto、owner challenge、trust/freshness；
- two-phase upload、secret quarantine、deterministic re-evaluation；
- public matrix、version diff、Badge、dispute/supersede；
- allowlisted project-operated runner；
- Docker Compose self-host；
- Registry operations、incident、backup/restore runbooks。

Exit evidence：

- 20+ 不同 runtime/version/config/client 组合，至少 5 个项目所有者确认；
- 90% hosted observations 在 freshness window 内；
- 两个独立 runner 对相同不可变目标的 verdict 一致率至少 95%；
- secret canary、SSRF、DNS rebinding、archive、stored XSS 测试全部通过；
- RPO/RTO 演练通过；
- 一名外部安全人员完成 threat model review；
- dispute 流程用模拟案例完整演练。

### 24.7 阶段 4：v1.0 RC 与 GA

RC 前冻结：

- CLI、config、exit codes；
- result/observation/schema；
- pack/profile identity；
- Driver RPC；
- Registry API v1；
- release、support、deprecation policy。

RC 期只接受 bug、安全、文档和经 TSC 批准的 compatibility fix。RC clock 从最终 public-contract digest 的首个 RC 开始；至少完整 6 周、两个 RC。任何 breaking CLI/schema/RPC/API/config 变化将 clock 清零，并重新要求该 digest 下两个 RC。五个 adopter 必须在同一 6 周 window 内各自至少 4 个不同周产生验证运行。

GA 不以某个日期或 Star 数触发，只以第 30 节 Definition of Done 触发。

### 24.8 阶段 5：GA 后

候选方向按真实需求排序：

- Google Interactions 完整 state/function loop；
- MCP 2025-11-25 stable conformance 深化；
- OpenAI Agents SDK、Claude Agent SDK、LangGraph；
- Realtime/WebSocket 独立 pack；
- 多模态 tool inputs；
- OpenTelemetry/OpenInference correlation；
- 企业离线 Registry 与 policy pack；
- 兼容问题公开数据集和年度论文。

不得在核心稳定前用更多 provider logo 掩盖深度不足。

---

## 25. Epic、依赖与验收

### 25.1 依赖图

~~~mermaid
flowchart TD
    E0["E00 战略与治理"] --> E1["E01 Contract 与规范库"]
    E1 --> E2["E02 Engine 与 Planner"]
    E1 --> E3["E03 Wire 与 Evidence"]
    E2 --> E4["E04 Oracle 与 Reference"]
    E3 --> E4
    E4 --> E5["E05 Chat / Responses packs"]
    E5 --> E6["E06 SDK / Agent drivers"]
    E6 --> E7["E07 归因与最小化"]
    E7 --> E8["E08 CI 与报告产品化"]
    E8 --> E9["E09 Registry"]
    E5 --> E10["E10 Google / MCP / Extensions"]
    E10 --> E9
    E9 --> E11["E11 GA 安全与发布"]
~~~

### 25.2 Epic 清单

| ID | Epic | 依赖 | 完成定义 |
|---|---|---|---|
| E00 | 战略、命名、治理基线 | 无 | 差异化 go 决策、名称可用、License/DCO/治理/安全入口完成 |
| E01 | Public contracts 与 Requirement Catalog | E00 | schema、版本、source snapshot、ambiguity 流程可生成和校验 |
| E02 | Planner、Budget、Scheduler、Config | E01 | IntentPlan/ResolvedRunPlan 确定、预算边界、resume/interrupt/exit code 可测 |
| E03 | HTTP/SSE Recorder、Redactor、Evidence CAS | E01 | 明确 capture layer 的 source-faithful application observation、streaming-safe、写盘前脱敏、可 replay/re-evaluate |
| E04 | IR、FSM、Oracle、Reference/Mutant Framework | E02,E03 | bootstrap meta-pack 通过；framework oracle 杀死定向 meta-mutants |
| E05 | OpenAI Chat、Responses、Anthropic core packs | E04 | 三个 core protocol packs 达到 Tier 1，Codex 所需 Responses 行为覆盖 |
| E06 | SDK/Agent Driver Runtime 与 Profiles | E05 | §6.1 全部 Tier 1 driver/profile、真实 client observation、版本/镜像固定 |
| E07 | Attribution、Differential、Minimizer、Repro | E06 | 有置信度的故障域、最小复现与 issue bundle |
| E08 | Reports、Baseline、GitHub CI 集成 | E07 | terminal/JSON/JUnit/SARIF/Markdown/offline HTML 稳定，5 个真实 repo 接入 |
| E09 | Signed Registry 与 Public Matrix | E08,E10 | trust/freshness/ownership/dispute/self-host/project-operated runner |
| E10 | Google、MCP 与 External/Dialect Extensions | E05 | 按 Tier 2 承诺实现，未知事件和 extension policy 完整 |
| E11 | GA security、release、docs、operations | 全部 | 第 30 节 DoD 全部满足 |

### 25.3 E00：战略、命名与治理基线

工作包：

- 完成竞品功能/架构/社区矩阵和作者沟通；
- 选定名称、logo 使用边界、Go module、GitHub org/repo、OCI namespace；
- 创建章程、Roadmap、Governance、Security、Data Policy；
- 设立 TSC 形成路径和利益冲突政策；
- 建立公开需求访谈记录与 design partner 名单；
- 确定项目是否独立、合作或贡献现有仓库。

验收：

- 至少 5 位来自 runtime/gateway/agent 生态的访谈，3 位愿意试用；
- 直接竞品差异可用 3 句事实说明，且不是“界面更好”；
- 名称没有明显 GitHub/package/domain 冲突；
- 源码仓库贡献的 DCO/License 与 Registry 上传的 Terms/Data License 边界分别清楚；
- go/no-go 由至少两名非作者评审。

### 25.4 E01：Contract 与规范库

工作包：

- 定义 Result、Evidence、IntentPlan/ResolvedRunPlan、Pack、Profile、Driver、Observation schema；
- 编写 canonicalization、unknown field 和 evolution policy；
- 建 source fetch/snapshot/diff 工具，只保存许可允许的内容；
- Requirement Catalog 支持 MUST/SHOULD/MAY、scope、revision、ambiguity；
- 生成 schema docs、sample、migration fixture；
- Pack compiler 做 dependency、capability、budget 和 CEL type check。

验收：

- schema 有正/负 fixture、版本兼容测试和 deterministic digest；
- 每个 normative assertion 在 CI 中验证 requirement link；
- source 更新只创建 drift PR，不自动改变 verdict；
- 同一 pack 在三平台编译 digest 相同；
- 旧 reader 面对 additive unknown fields 不崩溃。

### 25.5 E02：Engine、Planner 与 Budget

工作包：

- Config merge、secret refs、effective config；
- IntentPlan、受限 target preflight/CapabilityObservation、ResolvedRunPlan；
- deterministic resolver/planner、scenario DAG、dependency/skip reason/denominator digest；
- token bucket、并发档、四类预算、deadline；
- journal、resume、graceful cancellation；
- ResourceLease、reserved cleanup budget、crash recovery finalizer；
- run lifecycle、exit codes、structured logs。

验收：

- plan-only 不出网且输出 canonical IntentPlan；授权 resolve 后输出独立 ResolvedRunPlan；
- capability probe 不可修改 IntentPlan，只能通过 versioned resolver 产生新 digest；
- request、wall-time、response/artifact bytes 等 hard budget 有边界证明；token/cost 等 advisory/reservation budget 报告明确的最大 overshoot；
- crash/kill 后完成项可恢复，进行中项产生新 attempt；
- success/fail/cancel/budget/crash 路径均释放 reversible resources，残留有独立 finding；
- 相同输入计划逐字节一致。

### 25.6 E03：Wire、Redaction 与 Evidence

工作包：

- HTTP request/response、TLS metadata、SSE line/event、cancel/error recorder；
- local forward proxy 供真实 SDK 使用；
- content-addressed chunk、manifest、SQLite 可重建索引；
- strict/debug/synthetic/metadata-only capture；
- secret/PII redaction、upload preview、artifact scanner；
- replay transport 和 clock。

验收：

- 任意合法 chunk boundary 不改变 logical event；
- recorder 在声明的 application capture layer 不修复、不重排、不吞掉观察 bytes，并明确 proxy/rechunk/redaction 差异；
- 预置 canary secrets 在所有 report/artifact 中为零；
- 100 MiB trace 流式处理符合内存预算；
- malformed/slow/compressed response fuzz 无 crash/泄漏；
- replay 可离线重现同一 oracle verdict。

### 25.7 E04：Oracle 与参考实现

工作包：

- JSON/schema、FSM、relational、metamorphic、behavioral oracle primitives；
- provider-neutral IR 与 raw pointer；
- deterministic controlled backend；
- pack-conforming reference server 覆盖当前解释的合法边界；
- mutant server：字段缺失、类型错、index/call ID 错、event 顺序错、终止缺失、UTF-8/JSON fragment 错；
- property generators 与 shrinker。

验收：

- bootstrap meta-pack 在 pack-conforming reference framework 100% pass；
- 至少 10 个 framework-level meta-mutants 验证 schema/FSM/relational/oracle plumbing；
- oracle 失败都包含 requirement、expected、actual、evidence offset；
- IR 丢失 provider extension 时 CI 失败；
- framework mutation score 为 100%；真实 core packs 的 50-mutant gate 属于 E05/P03，避免 E04 依赖尚未实现的 pack。

### 25.8 E05：OpenAI Chat、Responses、Anthropic 与 Codex

工作包：

- Chat non-stream/stream、tools、structured output、errors/usage；
- Responses typed items、state、function calls/results、parallel calls、stream event FSM；
- store/previous response/conversation 的受控状态；
- reasoning summary/opaque item 仅验证公开契约；
- Anthropic version/content blocks、tool use/result、stream accumulator 与 unknown-event tolerance；
- Codex strict profile 与可选 WebSocket 扩展；
- official source revision 和 ambiguity notes。

验收：

- Tier 1 scenario 数和 requirement 覆盖达到本 Epic/P03 门槛；
- 官方 OpenAI SDK 当前受支持版本消费 pack-conforming reference server；
- Anthropic Messages pack 达到第 6.5 节 Tier 1，并可供 Python/Node Driver 消费；
- Codex profile 使用 Responses，不以 Chat 适配假装通过；
- parallel tool delta、content index、missing terminal、call ID 等历史 bug 全有 fixture；
- strict 与 dialect adapter 结果分栏，不静默 coercion。
- Chat/Responses/Anthropic 合计至少 150 unique scenarios、50 个 non-equivalent targeted mutants，normative mutation score 100%。

### 25.9 E06：Driver 与 Client Profiles

工作包：

- JSON-RPC over NDJSON lifecycle、capability negotiation、heartbeat、cancel；
- Python、Node runner image 与 lockfile；
- OpenAI Python/Node、Anthropic Python/Node、Vercel AI SDK、Codex、OpenClaw profile，以及 LiteLLM runtime profile；
- SDK observation hooks 与 raw proxy correlation；
- support-lock 中 previous/current 两个 Tier 1 版本，加 candidate 非阻断 canary；driver conformance kit；
- sandbox、env allowlist、resource limits。

验收：

- 每个 driver 对 reference 与 mutant 都给预期 observation；
- driver crash 与 target failure 不混淆；
- version/image/digest 全进入 report；
- 新 driver 作者只依赖公开 contract 和 conformance kit；
- 8 个 Tier 1 driver identity 在 nightly matrix 可重复运行；
- sandbox escape、env leak、path escape 测试通过。

### 25.10 E07：归因、差分与最小复现

工作包：

- raw vs SDK、stream vs non-stream、target vs controlled backend、direct vs gateway 差分；
- rule-based attribution graph 和 evidence-weighted confidence；
- request/tool/schema/turn/chunk/event delta debugging；
- failure fingerprint 抵抗动态 ID/time；
- curl、Python、Node、client-specific repro；
- issue template、environment manifest、upstream routing。

验收：

- ground-truth 集合的 false positive 低于 3%；
- 没有充分证据时输出 unknown + alternatives，而非猜测；
- 90% 历史 fixture 最小化后保留指纹；
- 中位 artifact/request 缩减至少 50%；
- repro 在干净容器一条命令重现；
- issue bundle 默认无 secret、私有 host 与真实内容。

### 25.11 E08：报告、Baseline 与 CI

工作包：

- terminal、stable JSON、JUnit、SARIF、Markdown、offline HTML；
- baseline accept/diff 与 pack denominator guard；
- annotations、artifact upload、PR summary；
- GitHub Action、reusable workflow、Docker action；
- cache、offline mode、proxy、enterprise CA；
- install/uninstall 和 shell completion。

验收：

- 六种核心格式从同一 result model 生成，不各自重算；
- HTML 无网络也可读并通过 CSP/XSS 测试；
- baseline 不可跨 digest 偷算百分比；
- GitHub fork PR 不获得 secret；
- 5 个外部 repo 连续四周在 PR/nightly 使用；
- 错误信息均给本地复现和下一步。

### 25.12 E09：Registry 与 Matrix

工作包：

- 第 19 节全部 schema、API、trust、freshness；
- owner challenge、OIDC identity、attestation；
- two-phase ingest、quarantine、re-evaluation；
- Postgres/object/OCI/static UI；
- allowlisted runner、SSRF control；
- dispute/tombstone/supersede、self-host、backup/restore。

验收：

- 第 24.6 节全部 exit evidence；
- 相同 observation 重复 commit 幂等；
- 修改任意 byte 会破坏 digest/signature；
- secret canary 永不进入公开对象；
- UI 无单一误导总分；
- 所有 admin action 有 audit event；
- 公共站故障不影响本地 CLI 和离线验证。

### 25.13 E10：Google、MCP 与 External/Dialect Extensions

工作包：

- Google generateContent 与 Interactions 分开建模；
- MCP 2025-11-25 JSON-RPC lifecycle、capability、tools/resources/prompts、cancel/error；
- Open Responses 作为 ExternalSuiteAdapter；OpenRouter 作为 ProviderConnectionProfile + 明确 DialectAdapter；Ollama native API 使用独立 ProtocolPack，其 /v1 方言另用 DialectAdapter；
- unknown event/field forward compatibility；
- provider-native 字段/类型可通过 typed extension 与 evidence pointer 完整追溯。

验收：

- 每个 protocol 的来源、stability、support tier 清楚；
- 不把 OpenAI 字段语义直接套到 Anthropic/Google；
- Google native function args object 不被错误字符串化；
- MCP 只以当前 stable revision 宣称 normative；
- extension pass 不覆盖 core strict fail。

### 25.14 E11：GA 工程化

工作包：

- 安全评审/渗透、SBOM/provenance/signing；
- upgrade/migration/compat policy；
- 全文档、教程、API reference、双语核心内容；
- governance roles、release rotation、support；
- RC、adopter 迁移、incident/recovery drill；
- OpenSSF badge 与 ADOPTERS。

验收：第 30 节所有 checkbox 有证据链接和 owner；不是仅由项目作者自行声明。

### 25.15 Issue 质量标准

每个 implementation issue 使用：

~~~yaml
problem: 用户或系统痛点
scope: 明确包含与排除
requirements: 对应 requirement/RFC/ADR
interfaces: 影响的 public contract
security_privacy: 风险与数据
test_plan:
  reference_pass: ...
  mutant_fail: ...
  negative: ...
  cross_platform: ...
acceptance:
  - 可二元验证的条件
artifacts:
  - fixture/report/docs/migration
dependencies: []
owner: role
~~~

不得用“实现 streaming 支持”这类无法验收的标题代替行为边界。单个 PR 尽量只改变一个 public contract 或一个可独立验证的 vertical slice。

---

## 26. Codex 驱动的实施方式

### 26.1 Codex 最适合承担的工作

- 从一手 issue/规范中提取候选 requirement，随后由人复核；
- 将公开故障重写为合成 fixture；
- 批量生成 reference/mutant 配对测试；
- 对 parser、state machine、redactor 做 fuzz/property cases；
- 实现重复性强的 SDK driver、schema docs、migration fixtures；
- 对失败 trace 做 delta debugging 候选；
- 生成上游 issue/PR 草稿和复现说明；
- 执行跨文件机械迁移与测试补全。

不应无人复核地交给 Codex：

- 解释含糊 normative 规范；
- 宣布某厂商不兼容；
- 安全边界、密码学或 sandbox 最终批准；
- 删除/公开用户 artifact；
- Registry 争议结论；
- License、商标、治理决策；
- 真实密钥与生产公共 runner 操作。

### 26.2 AGENTS.md 核心规则

~~~text
1. 没有 Requirement Catalog 来源，不新增 normative assertion。
2. 不把 model failure、wire failure、client failure 合并。
3. 每个 bug fix 增加最小 fixture；每个 assertion 增加 reference pass + mutant fail。
4. Unit/golden test 禁止网络；live provider 只在专门 canary workflow。
5. 测试不得读取用户 HOME、真实 .env 或系统 keychain。
6. Provider payload 在日志、snapshot、PR 前必须经过 redaction。
7. 不用 retry 隐藏 flaky；保留 attempt 与原因。
8. 不修改已发布 pack/profile digest。
9. Public schema 变更需要 migration、compat test 和 RFC/ADR。
10. 先运行目标包测试，再运行全量质量门禁；在 PR 写出命令和结果。
11. 不复制许可证不明的竞品测试；采用 independent reimplementation 并记录来源事实。
12. 遇到规范歧义时停止硬编码，创建 ambiguity note。
~~~

### 26.3 并行工作模型

每个较大能力采用四角色：

1. Spec researcher：收集一手来源与历史 bug；
2. Implementer：实现 vertical slice；
3. Adversarial tester：写 mutant、fuzz、边界；
4. Reviewer：检查证据、隐私、兼容与文档。

角色可以由一人和多个 Codex agent 承担，但同一上下文生成的实现与测试不能被视为真正独立审查。关键 pack 至少由另一位人类维护者复核。

使用独立 worktree/branch：

~~~text
work/spec-<protocol>
work/engine-<component>
work/driver-<client>
work/corpus-<issue>
work/security-<control>
~~~

合并顺序是 source/requirement → failing fixture/mutant → implementation → docs/report example。这样 PR 能证明测试在修复前确实失败。

### 26.4 Codex 配额建议

将富余 Codex 额度投入高社区复利工作：

| 比例 | 工作 |
|---:|---|
| 40% | 上游 issue 重现、最小化、回归 fixture |
| 25% | mutation/property/fuzz corpus 与跨 SDK matrix |
| 20% | driver、文档、迁移和 contribution scaffolding |
| 15% | 上游补丁草稿、review、issue bundle 质量提升 |

每周期望产物，不以生成代码行数衡量：

- 5 个一手问题完成重现/判定；
- 3 个最小 fixture + mutant；
- 1 个能送往上游的高质量 issue 或 PR；
- 1 次 pack/source drift 审查；
- 所有合并代码有人类验收证据。

禁止自动向大量上游发 PR、Issue 或评论。任何外部沟通由人确认目标、复现、措辞和维护者偏好，避免把社区当作 Codex 输出消化器。

### 26.5 Definition of Ready

Issue 开工前必须具备：

- 用户/上游痛点；
- scope 与非目标；
- 来源或 RFC；
- 输入/输出 contract；
- reference 与 negative/mutant 测试方案；
- 安全/隐私评估；
- acceptance criteria；
- owner 与依赖。

缺少规范事实时，先做 research issue；缺少用户价值时，不以“架构很优雅”为理由开工。

### 26.6 Definition of Done

单个 change 完成：

- 行为实现并通过目标、全量、race/fuzz regression；
- reference pass、mutant/negative fail；
- public contract/schema/migration 已更新；
- failure 有 evidence pointer 和 actionable message；
- secret/privacy/security 检查通过；
- 文档、示例、changelog/ADR 视影响更新；
- 监控/metrics 可观测；
- reviewer 能从干净环境重现；
- 没有遗留无 owner 的 TODO。

---

## 27. 风险登记、触发器与应对

| 风险 | 概率/影响 | 早期触发器 | 应对 | Owner |
|---|---|---|---|---|
| 与 octest 等高度重复 | 高/高 | 用户只需要 basic probe；竞品快速补齐 SDK/Registry | 第 0 阶段主动合作；共享格式；必要时合并或转为专门 pack/fuzz 项目 | TSC |
| 规范漂移 | 高/高 | 官方文档/SDK 行为变更，nightly canary 同时失败 | source revision/diff、不可变 pack、人工 RFC、旧结果分代 | Pack Maintainer |
| 模型随机性造成误报 | 高/高 | 同 wire config verdict 反复变化 | deterministic backend、分层 verdict、重复与置信区间、unknown | Test Lead |
| 组合爆炸 | 高/高 | matrix 时长/成本月增超过采用速度 | tier/profile、pairwise、risk-based selection、预算 | Release/TSC |
| 真实 API 成本失控 | 中/高 | canary 预算连续两周超标 | 专用账户、hard budget、synthetic first、社区 owner-run | Operations |
| Target 识别测试并作弊 | 中/高 | public runner 显著优于独立本地 | 动态等价 mutation、隐藏 seed、独立重现、无单总分 | Registry |
| 错误公开结论损害声誉 | 中/高 | 争议率高、false positive 超过 3% | evidence-first、confidence、owner response、快速 dispute、禁“认证”措辞 | TSC |
| Secret/私有 trace 泄露 | 中/极高 | scanner 命中或用户投诉 | 写盘前 redaction、上传预览、quarantine、事件 runbook | Security |
| Registry SSRF/滥用 | 中/极高 | 非所有者 URL、内网解析、异常出网 | ownership/allowlist、egress proxy、重解析、硬配额 | Security/Ops |
| 恶意 endpoint/driver 接管 runner | 中/极高 | sandbox violation、资源异常 | 声明 pack、driver isolation、公共 allowlist、microVM 高风险层 | Security |
| SDK/Client 为闭源且行为变化 | 高/中 | 无法固定版本或自动安装 | 明确 observed profile、保存 artifact digest、只承诺可获得版本 | Driver Maintainer |
| Registry 运维吞噬核心开发 | 中/高 | 运维工时超过总工时 40% | static-first、自托管、托管 beta、容量门禁 | TSC |
| Vendor capture | 中/高 | 单一雇主控制审批/数据 | TSC 上限、两组织审批、COI、赞助隔离 | Governance |
| 单人倦怠/Bus factor | 高/高 | 两个 release 只有一人、issue 积压 | 贡献最小单元、release rotation、缩 scope、不无限开协议 | TSC |
| Stars 多但无人 CI 使用 | 高/高 | 流量来自发布帖，4 周后无复跑 | North Star 用上游确认/CI adoption，优先 integration 与 issue bundle | Product |
| Fixture 版权/隐私问题 | 中/高 | 直接复制日志/SDK tests | 合成重写、provenance/license 字段、删除流程 | Corpus Maintainer |
| 测试产生真实副作用 | 低/极高 | endpoint 调用真实 tool | inert tools、受控 backend、side-effect classification、默认拒绝 | Security |
| 名称或商标冲突 | 中/中 | package/domain/律师异议 | 阶段 0 检索、工作名不固化、TRADEMARKS | TSC |
| “兼容百分比”被媒体误读 | 高/中 | 截图省略 profile/digest | 五维展示、无默认总榜、Badge 强制版本和信任 | Registry |

风险每月 review；概率/影响变化、触发器命中和 mitigation 状态写入公开 issue。安全细节可在私有 advisory 管理。

### 27.1 停止条件

第 6–8 周任一关键条件持续成立，停止独立大项目：

- 20 个真实 issue 中无法可靠重现 80%；
- 不能证明比现有 tester 增加 client-observed/attribution 价值；
- 找不到 3 位上游维护者愿意评审或试用；
- 无法把 wire/model/client 故障分开，误报不可控；
- 竞品已开放承载完整范围且合作更节省社区成本。

公开发布后第 3–4 月：

- 没有任何外部 CI integration；
- 没有外部 fixture/pack/driver contributor；
- false positive 长期高于 10%；
- 用户认为生成的 repro 并未节省调试时间；
- 绝大多数使用只停留在 basic health probe。

第 9–12 月：

- 少于 5 个持续 CI adopter；
- 连续 90 天没有上游确认 finding；
- Registry 大量 stale 且无人维护；
- 仍只有一人能发布；
- Registry 运维长期超过核心改进工作。

### 27.2 Pivot 选项

停止完整愿景不等于丢弃成果，可转向：

1. 将高质量 Responses/Anthropic pack 捐给 Open Responses 或现有 tester；
2. 专做 SDK/client compatibility profiles；
3. 专做 SSE/tool-call protocol fuzz corpus；
4. 专做 failure minimizer 与 upstream issue bundle；
5. 发布 corpus/requirement catalog 供多个 runner 消费；
6. 成为现有 runtime 的 conformance working group。

Pivot 决策保存 schema、fixture 和证据的开放可移植性，不用 sunk cost 维持无人采用的托管平台。

---

## 28. 社区采用、传播与增长

### 28.1 增长飞轮

~~~mermaid
flowchart TD
    A["真实上游故障"] --> B["最小可复现证据"]
    B --> C["高质量 Issue / PR"]
    C --> D["上游修复与回归测试"]
    D --> E["项目文档引用 Doctor"]
    E --> F["更多 CI adopter 与 observations"]
    F --> A
~~~

高 Star 的可持续来源是成为维护者解决真实 bug 的基础设施，而不是一次发布帖。每个已确认 finding 都应回链：

- Doctor corpus → upstream issue；
- upstream issue → fix PR；
- fix PR → regression fixture；
- Registry observation → fixed version；
- README case study → 对维护者节省的时间。

### 28.2 首发门槛

对外大规模发布前至少：

- 30 个有 provenance 的历史问题；
- 5 个项目、10 个以上版本/配置组合；
- OpenAI Responses、Chat、Anthropic 三个有深度的 protocol packs；
- Python/Node SDK、Codex/Vercel 等至少 3 个 client profiles；
- 5 个可公开展示的 issue bundle；
- 2 位非核心作者的上游维护者 endorsement；
- 一个 60 秒从 test → failure attribution → minimal repro 的真实录屏；
- 一个 honest comparison 页面，明确竞品更适合的场景；
- 安装、验签、quickstart、数据隐私页面完成。

### 28.3 发布顺序

1. 先向参与 corpus 的上游维护者私下/Issue 中提供复现，尊重其披露和修复节奏；
2. 在 2–3 个 runtime/gateway 中落地 CI；
3. 发布 case study，不以空泛 feature list 为主；
4. GitHub Release、Show HN、Hacker News、LocalLLaMA、V2EX/中文技术社区；
5. 针对 Go/AI infra podcast、newsletter 和 conference 投稿；
6. 每月 Compatibility Drift Brief；
7. 每季度公开 failure taxonomy 和已修复问题。

不在不同仓库复制粘贴宣传，不给未参与者批量 @mention，不用“100% compatible”标题。

### 28.4 内容资产

- “为什么 curl 成功但 Codex/Vercel 失败”交互式 report；
- 一页 Responses streaming event 状态机；
- vLLM/llama.cpp/LiteLLM 已修复真实案例；
- “实现 OpenAI compatible endpoint 最常见的 20 个坑”；
- 每个 client 的可复制 CI recipe；
- protocol drift changelog；
- public mutant challenge：实现者可本地验证测试是否能抓到故障；
- 年度 State of Agent API Compatibility 报告。

所有内容引用可验证 observation，不做厂商拉踩。

### 28.5 贡献者增长

- good first fixture、good first mutant、driver version bump 三类模板；
- 每月一次 corpus sprint；
- 上游项目可以共同维护自己的 profile，但必须遵守独立 review；
- 为合并的 fixture/pack/driver contributor 在 release notes 与站点署名；
- 自动生成 contributor setup 与本地验证命令；
- 对第一次贡献提供明确、快速、技术性的 review；
- 小贡献也能进入 ADOPTERS/case study，不要求先理解整个 engine。

### 28.6 指标

| 类别 | 指标 | 目标/解释 |
|---|---|---|
| North Star | 每月被上游确认或修复的独立兼容问题 | 核心价值 |
| Adoption | 持续 4 周以上的外部 CI repo | GA 至少 5 |
| Reproduction | Issue Bundle 被上游首次复现的比例与耗时 | 目标 80% 在 30 分钟内 |
| Quality | ground-truth false positive | GA 低于 3% |
| Reliability | 独立重跑 verdict 一致率 | 至少 95% |
| Coverage | requirement、mutant、historical bug、client matrix | 显示绝对分母，不只百分比 |
| Freshness | window 内 public observations | 至少 90% |
| Community | 外部 maintainer、活跃 contributor、bus factor | GA 3 maintainer/3 independent orgs |
| Upstream | merged fix/regression test、项目文档引用 | 比下载更重要 |
| Usage | 月活本地 runs、report opens，只有 opt-in/公共数据 | 不牺牲隐私 |
| Reach | unique cloners、release downloads、Stars、Followers | 滞后传播指标，不作为兼容成功 |

不要承诺 Star 数。可以设传播实验目标，例如首发后 30 天获得 500 个真实 unique cloners、20 个 issue bundle 使用者；但若 Stars 高而 CI adoption/上游确认低，视为定位未验证。

### 28.7 可持续资金

允许：

- 无附加测试特权的公开赞助；
- 基金会/研究 grant；
- 托管 Registry 的透明成本赞助；
- 企业支持、私有部署服务，与开源 conformance 结果隔离。

不允许：

- 付费删除失败；
- 付费获得更高 trust/compatibility label；
- 私有修复后不更新公开 pack；
- sponsor 独占规范解释；
- 销售用户上传的 trace 或行为数据。

年度透明报告列出收入、基础设施成本、主要赞助与潜在利益冲突。

---

## 29. Codex Goal Mode 分阶段执行与收敛协议

### 29.1 为什么不能用一个无限大 Goal

Codex 官方建议 Goal 具备一个 durable objective、一个可验证 stopping condition、明确上下文、验证命令和 checkpoint；好的 Goal 应大于单轮 prompt，但小于开放式 backlog。[Follow a goal](https://developers.openai.com/codex/use-cases/follow-goals) 还明确建议保留短 progress log。CLI 的 Goal objective 最多 4,000 字符，较长细节应放在文件中并让 Goal 指向它：[Codex slash commands](https://developers.openai.com/codex/cli/slash-commands)。

因此不要只输入：

~~~text
/goal 实现完整 Plan.md，直到成熟。
~~~

这会让“成熟”不可计算，容易发生范围扩张、测试降级或在关键人工决策上自作主张。

本项目采用：

> 一个长期愿景，九个 Implementation Phase，每个 Phase 再拆成有序 Work Unit；一次 /goal 只完成 phase-state 中唯一 activeWorkUnit。所有 Work Unit 收敛后，Phase aggregate gate 才能收敛。

完成九个 phase 就是实现完整代码，而不是缩小最终范围。Phase 是产品/架构边界，Work Unit 是 Goal 的有界执行边界；P04–P08 这类多月工程绝不能作为一次 Goal。

### 29.2 Agent 状态文件

P00.B00 获批并由受保护 workflow 创建 Genesis 后，仓库具有以下权威执行状态结构；Genesis 前不得创建或手写 phase-state.yaml/transitions：

~~~text
execution/
├── README.md
├── phase-state.yaml
├── transitions/
├── impact-map.yaml
├── product-stage-map.yaml
├── progress.md
├── decisions.md
├── blockers.md
├── waivers.yaml
├── phases/
├── work-units/
├── approval-requests/
├── approvals/
├── metrics/
│   ├── definitions.yaml
│   └── latest.json
└── gates/
    ├── p00/
    ├── p01/
    └── ...
~~~

transitions/ 中 append-only、签名、hash-chained 的 StateEvent attestations 是唯一权威状态源；事件 kind 至少有 Genesis、StateTransition 和 EvidenceAttachment。phase-state.yaml 是 `doctor phase state-verify` 重放后生成的只读视图，方便 Agent 读取。以下示例表示 P00.B00 已获批准、受保护 workflow 已激活 P00.W01 之后的状态，不是 bootstrap 前可以由 Agent 自行写入的初始状态：

~~~yaml
schemaVersion: urn:agentapi-doctor:execution:v1
planVersion: "1.0"
activePhase: P00
activeWorkUnit: P00.W01
pendingWorkUnit: null
phases:
  P00:
    status: ACTIVE
    aggregateContractDigest: sha256:...
    controlPlaneDigest: sha256:...
    baseCommit: ...
    startedAt: ...
    prerequisites: []
    requiredGates:
      - make gate PHASE=P00
    humanGate: required
    lastEvidence: execution/gates/p00/latest.json
    attempts: 0
    noProgressAttempts: 0
    blockers: []
    workUnits:
      P00.W01:
        status: ACTIVE
        contractDigest: sha256:...
        approvalDigest: sha256:...
~~~

允许状态：

- NOT_STARTED：前置条件未满足；
- READY：前置满足，尚未开工；
- ACTIVE：唯一当前 phase；
- BLOCKED：触发暂停条件，需要人或外部信息；
- WAITING_EXTERNAL：机器工作完成，等待采用、时间窗、外部审计等证据；
- REVIEW_PENDING：机器/外部条件齐备，等待人工 gate；
- MACHINE_CONVERGED：全部 MACHINE criteria 通过；后续可能转 WAITING_EXTERNAL 或 REVIEW_PENDING；
- CONVERGED：机器和人工门禁通过；
- REJECTED：阶段证据无效，需要回到 ACTIVE；
- SUPERSEDED：Plan/RFC 明确替换。

每个 StateTransition 记录 event_id/previous_digest、unit/phase、from/to、sourceCommit、controlPlane/evidence/approval digests、actor identity/role、timestamp、reason 和 signature。EvidenceAttachment 不改变状态，只能为同一 sourceCommit/controlPlaneDigest 追加 pair evidence/index pointer，并记录 event_id/previous_digest、evidence kind/digest、actor/timestamp/signature；它不能替代需要状态改变的 StateTransition。`doctor phase state-verify` 必须从 genesis 重放并验证事件 kind、允许转换、attachment 绑定、签名、唯一 active pointer 和 digest；直接编辑 phase-state.yaml、脱链 attachment 或缺少 transition 的状态变化都会失败。

任何时刻最多一个 activePhase 和一个 activeWorkUnit。Goal 只能处理 activeWorkUnit，不得在多个 READY 中自行选择。`doctor phase activate Pxx --unit Pxx.Wyy --attestation <path>` 是受保护 workflow 创建 StateTransition 的唯一激活入口；它验证前置 evidence、contract approval 和 impact-map。Agent 不得直接改变权威状态或把需要人工 gate 的 Work Unit/Phase 改为 CONVERGED。

activeWorkUnit 非空当且仅当该 unit 状态为 ACTIVE。进入 MACHINE_CONVERGED、BLOCKED、WAITING_EXTERNAL 或 REVIEW_PENDING 时，transition 将其移到 pendingWorkUnit 并清空 activeWorkUnit；只有受保护的 `doctor phase resume ... --attestation <path>` / `doctor phase activate ... --attestation <path>` 可恢复 ACTIVE。除 §34.2 明确定义、运行于 Genesis 之前的 P00.B00 bootstrap Goal 外，任何 Goal 发现 activeWorkUnit 为空都必须立即拒绝执行，不得拿 pending/READY 猜工作。

允许的普通转换：

~~~text
NOT_STARTED → READY | REJECTED | SUPERSEDED
READY → ACTIVE | REJECTED | SUPERSEDED
ACTIVE → MACHINE_CONVERGED | BLOCKED | REJECTED | SUPERSEDED
BLOCKED → ACTIVE | REJECTED | SUPERSEDED
MACHINE_CONVERGED → CONVERGED | WAITING_EXTERNAL | REVIEW_PENDING | REJECTED
WAITING_EXTERNAL → CONVERGED | REVIEW_PENDING | REJECTED
REVIEW_PENDING → CONVERGED | REJECTED
CONVERGED → REJECTED        # impact/control-plane invalidation only
REJECTED → READY            # 新 contract/evidence 获批后
~~~

`MACHINE_CONVERGED → CONVERGED` 和 `WAITING_EXTERNAL → CONVERGED` 只在 Goal Contract 的 applicable criteria 中没有未完成 HUMAN/TIME/EXTERNAL gate 时允许，并由受保护 workflow 证明 applicable set 与 attestation 均完整；Agent 不能直接执行。控制面/impact 失效时，ACTIVE 转 BLOCKED；READY、MACHINE_CONVERGED、WAITING_EXTERNAL、REVIEW_PENDING 或 CONVERGED 转 REJECTED；NOT_STARTED 在 contract 被取代时转 SUPERSEDED 或在新 contract 待批时转 REJECTED。这样“立即 BLOCKED/reopen”有唯一、状态相关的含义。其他转换由 `doctor phase state-verify` 一律拒绝。

progress.md 只追加短 checkpoint：

~~~text
2026-..-.. P02 checkpoint 04
Changed: upstream_application_observation now preserves observed SSE line endings
Verified: make test-recorder; 418 tests passed
Metric: mutant killed 17/20, previous 15/20
Remaining: gzip ratio guard, Windows cancellation
Blocked: no
Next: implement decompression ceiling mutant
~~~

decisions.md 记录临时实现决定及对应 ADR；blockers.md 记录需要人处理的问题；waivers.yaml 和 approvals/ 只能由人或独立受信 CI identity 写入，包含 owner/reviewer、source commit、contract/evidence digest、理由、范围、到期日期和补偿控制。Agent 只能写 approval-requests/ 草稿，不能填写 reviewer identity 或批准自己。

首次建仓使用 phase 外的 bootstrap review protocol，而不是第二套执行状态机：

~~~text
Agent 生成 P00.B00 candidate files
→ Agent 写 approval-requests/P00.B00（仅表示“请求待审”，不是权威 phase status）
→ 人/独立 reviewer 生成独立 approval attestation
→ 受保护 workflow 验签并创建 Genesis StateEvent、P00.W01 activation
→ state-verify 首次生成 phase-state.yaml
~~~

Genesis 前的权威事实只有不可变 candidate digests、approval request 与外部 approval attestation；不存在 activePhase/activeWorkUnit，也不存在可由 Agent 改写的 bootstrap 状态。approval 被拒绝时写新的 review attestation/request revision，不创建 Genesis。Genesis 必须绑定获批 controlPlaneDigest、candidate source commit、reviewer identity/signature，并把此前 request/approval digest 纳入链首。

B00 不适用普通 Work Unit convergence，也不能产生 completion evidence。B00 只生成 candidate control plane、gate/meta-tests 和 approval request；批准后 P00.W01 专门验证已冻结 gate，Run A/B 通过才可 MACHINE_CONVERGED。P00.W02 依赖 P00.W01 CONVERGED。

### 29.3 每个 Work Unit 的 Goal Contract

每个 Phase 有 aggregate contract，每个 Work Unit 在 execution/work-units/Pxx.Wyy.yaml 定义：

~~~yaml
id: P03.W02
phase: P03
title: OpenAI Responses strict pack
objective: Build the Responses HTTP/SSE strict pack and prove it against the frozen reference and mutant catalogs.
controlPlaneDigest: sha256:...
readFirst:
  - Plan.md
  - AGENTS.md
  - execution/phase-state.yaml
  - rfcs/0001-compatibility-layers.md
inScope:
  - packs/openai-responses-http
  - reference/server
  - reference/mutant-server
outOfScope:
  - registry
  - google
  - hosted provider rankings
protectedAcceptanceInputs:
  - requirements/openai-responses.lock
  - tests/acceptance/responses
  - fixtures/catalog/responses.lock
  - execution/metrics/definitions.yaml
mutableImplementationTests:
  - internal/**
  - test/regression/responses/**
prerequisites:
  - P03.W01: CONVERGED
deliverables:
  - strict pack artifacts
  - requirement coverage report
  - reference and mutant evidence
verification:
  - make test-responses
  - make mutation-responses
  - make gate-unit UNIT=P03.W02
convergence:
  - id: responses-required-behavior
    kind: MACHINE
    evaluator: evaluator://pack-gate/v1
    threshold: all_applicable_must
    datasetDigest: sha256:...
  - id: responses-pack-review
    kind: HUMAN
    evaluator: role://pack-maintainer
    threshold: approved
resourceBudget:
  wallTime: 8h
  commandTimeout: 30m
  fuzzCPUHours: 2
  diskBytes: 10GiB
  downloadBytes: 2GiB
  processLimit: 64
networkPolicy:
  gate: offline
  researchAllowlist:
    - developers.openai.com
  dependencyFetch: lockfile-only
stopAndBlock:
  - normative ambiguity without a cited decision
  - three attempts with the same failure fingerprint
humanGate: pack-maintainer-review
~~~

Goal Contract 的 objective、inScope、outOfScope、deliverables、verification、convergence、resourceBudget、networkPolicy、stopAndBlock 都必填。每条 convergence criterion 必须有 kind=MACHINE/EXTERNAL/TIME/HUMAN、命名 evaluator、threshold 和 evidence schema。

Goal 启动前，Work Unit Contract、gate runner、protectedAcceptanceInputs、fixture/denominator catalog、metrics definitions/evaluator digest 必须得到 commit-bound 人工或独立 reviewer approval。Agent 可起草 contract/gate，但不能批准自己的考试。修改受保护 oracle/assertion、golden semantics、fixture catalog、denominator/threshold 或 evaluator 会立即使当前 evidence 失效；ACTIVE unit 进入 BLOCKED，已有机器/外部/人工证据的非 ACTIVE unit 进入 REJECTED，直到新 digest 获得批准。

Agent 可以在 mutableImplementationTests 范围内新增或加强 unit/regression/property tests，不需每次重新批准；不得删除、跳过或放宽 protected acceptance，也不得把一个 acceptance test 搬到 mutable 区。test-policy evaluator 检查目录 ownership 和语义 diff。

controlPlaneDigest 覆盖 Plan.md、适用 RFC、Appendix C 的全部权威 manifests/locks、phase/work-unit contracts、gate/evaluator、protected acceptance inputs、catalog 和 schema index。每个 Goal approval、gate、human/external/time attestation 都必须绑定同一已批准 controlPlaneDigest。任何控制面变化按第 29.2 节转换表使 ACTIVE 进入 BLOCKED、已有证据的非 ACTIVE 状态进入 REJECTED，并要求独立批准；Agent 不能通过改 Tier、release scope、GA criteria、impact-map 或 generated docs 降低考试。

P00.B00 是 bootstrap 特例：第一个 Goal 只能生成 candidate contract/gate 和 anti-placeholder tests；人工锁定其 digest 后，受保护 workflow 才创建 P00.W01，第二个 Goal/clean-checkout run 才能产生有效 P00 evidence。降低门槛必须走 RFC；开发期 waiver 不能让未通过项变成 PASS。

### 29.4 通用收敛条件

一个 Work Unit 只有同时满足以下四类条件才是 MACHINE_CONVERGED；Phase aggregate 对全部 Work Unit 和跨单元 criteria 重复同一规则：

1. Functional convergence
   - 所有 contract deliverables 存在；
   - required behavior 通过，negative/mutant 行为按预期失败；
   - 没有 stub、panic placeholder、空 handler 或仅返回固定值的伪实现；
   - in-scope public API 有端到端调用路径。

2. Quality convergence
   - Work Unit targeted tests 全过；
   - repository required gate 全过；
   - race、lint、schema、secret/license 检查按 phase 要求通过；
   - 没有未隔离 flaky、P0/P1 issue 或无 owner 的 P2；
   - coverage/mutation/benchmark 门槛未通过时不能只改阈值。

3. Evidence convergence
   - execution/gates/pXX/<commit>.json 记录命令、exit code、时长、摘要和 artifact digest；Phase/Work Unit ID 用大写，文件目录固定小写；
   - 从 clean checkout 重跑 gate 成功；
   - 每个 deliverable 有 validatorId、语义 assertion、原始 evidence digest；路径存在或文件非空不算完成；
   - acceptance 条件有可重算 report/fixture/测试路径，不接受“看起来完成”或手填指标；
   - progress、decisions、known limitations 已更新。

4. Scope convergence
   - git diff 只包含 in-scope 或明确批准的依赖修改；
   - out-of-scope 想法进入 backlog，不顺手实现；
   - 没有通过删除 fixture、skip test、放宽 assertion、改变 denominator 来变绿；
   - public contract 变化有 migration/ADR/RFC。

CONVERGED 还要求对应外部/时间/人工 gate 按 contract 通过。人工 gate 关注机器不擅长独立决定的规范语义、隐私、安全、用户价值与公共声明。

make gate 只能执行 kind=MACHINE 的条件，并验证已导入、签名且 schema 合法的 EXTERNAL/TIME/HUMAN attestation；缺失外部证据不得记 pass。采用、跨平台 CI、外部审计、渗透测试、RC 等待和维护者数量绝不能由本地 Agent 自报。

#### 29.4.1 指标定义唯一来源

execution/metrics/definitions.yaml 是唯一指标定义源。每项比例必须固定 metric ID、公式、numerator、denominator、minimum N、dataset/catalog digest、时间窗、排除规则、unknown/quarantine 处理、置信方法和 evaluator digest；样本不足返回 insufficient_samples，不得 pass。

GA 初始定义：

| Metric | 定义与最小样本 |
|---|---|
| attribution_false_positive | 冻结双人裁决 ground-truth 集至少 200 cases、至少 5 个 fault classes、每类至少 20；错误的非-unknown 归因数 / 全部非-unknown 归因数；95% Wilson 上界小于 3%；unknown 仍保留在 eligible catalog |
| attribution_decision_coverage | non-unknown decision / 全部 eligible ground-truth cases；整体至少 80%，每个 fault class 至少 60%；与 false-positive 同时通过，防止全部输出 unknown |
| repro_preservation | 至少 100 个 distinct failure fingerprints、至少 5 类；最小化后满足原 k-of-n predicate 的数量 / 尝试数量；95% Wilson 下界至少 90% |
| minimization_reduction | canonical request bytes + required event bytes 的缩减比例；同一 100-case 集合的中位数至少 50%，不能靠删除复现所需 secret/metadata |
| evidence_recompute_consistency | 至少 10,000 个 frozen evidence/oracle/core/pack combinations 跨受支持 OS/arch 重算；逐字节 verdict JSON 必须 100% 相同，任一差异阻断 |
| end_to_end_rerun_consistency | 至少 100 个 runs、5 个 version-pinned targets、相同 config/profile/pack；相同 verdict fingerprint 比例至少 95%，同时展示 95% interval |
| deterministic_flaky_rate | 连续 14 个 nightly、至少 10,000 eligible deterministic test executions；非预期结果变化 / eligible executions 小于 0.1%，无未裁决 quarantine |
| registry_freshness | 所有未 tombstone 的 hosted observations 为分母，至少 20 个 subject/version/config/client combinations；30 天 window 内至少 90% |
| normative_mutation_score | killed non-equivalent targeted mutants / 全部 non-equivalent targeted mutants；equivalent mutant 需两名 reviewer 裁决并公开排除原因；Tier 1 为 100% |
| scenario_count | 唯一 scenario ID 且有不同 requirement/assertion purpose 才计数；alias、重命名、仅 fixture 参数重复不计；同时要求 taxonomy coverage |

Tier 1 不由一个比例决定，严格使用第 6.5 节全部条件。修改 definitions/dataset/denominator digest 会使相关历史 gate 失效并触发 impact-map reopen。

### 29.5 双运行、四步验证规则

冻结 source commit C 后执行两个独立 Run：

1. Run A：在开发环境执行 targeted gate 和 repository gate；
2. 销毁该执行环境；
3. Run B：从 C 的全新 checkout/容器执行 clean-checkout gate；
4. 在独立 verifier 中执行 evidence-verify。

Run A/B 绑定相同 Plan、Goal Contract、support lock、toolchain、gate/evaluator、protected acceptance、metric definition、dataset 和 dependency digests。Run B 使用临时 HOME、无未跟踪 mount、无凭据、gate 阶段断网；依赖必须预先按 lock/digest 准备。确定性 verdict/result artifact digest 必须与 Run A 相同；时间、主机名等非确定 metadata 存在单独 envelope，不进入 verdict digest。

这里的“两次成功”只指 Run A 和 Run B，不是四个命令中的任意两个。两次之间不得修改 source。若只修改纯文档，重新运行 docs/link/schema/manifest 影响 gate；若修改 executable、schema、protected fixture/acceptance、dependency、gate、contract、安全边界或其 impact-map 路径，Run A/B 全部失效并从新 source commit 重跑。新增 mutable regression test 仍需生成新 source commit 并重跑 Run A/B，但不要求重新批准 contract。

建议统一命令：

~~~text
make bootstrap
make verify
make state-verify
make control-plane-verify
make gate-unit UNIT=P00.W01
make gate PHASE=P00
make gate PHASE=P01
...
make gate PHASE=P08
make gate-all
make evidence-verify PHASE=Pxx
make clean-checkout PHASE=Pxx
make ga-gate
~~~

第一阶段必须实现这些命令的真实 orchestrator 和 anti-placeholder meta-tests；它们不能是永远返回 0、只检查文件存在或读取手填数值的 placeholder。尚无对应能力时明确 fail 并输出 missing evaluator/gate。

### 29.6 迭代收敛与暂停条件

每次 meaningful iteration 必须改变代码/fixture/设计并运行最小验证。以下任一发生时，Goal 必须暂停并标记 BLOCKED：

- 同一 failure fingerprint 连续 3 次没有变化；
- 连续 5 个 meaningful iterations，核心通过数、mutation score、失败规模或明确 blocker 均无改善；
- 需要未获授权的真实密钥、付费资源、外部发布、删除数据或扩大网络权限；
- 出现无一手来源可裁决的 normative ambiguity；
- 必须改变已冻结 public contract 或降低 phase gate；
- 发现高危安全问题、secret exposure 或许可证冲突；
- 前置 phase 的 evidence 被证明无效；
- 剩余工作全部在 out-of-scope；
- wall-time、token/额度或 provider cost 达到用户为该 Goal 设置的硬预算；
- 下载字节、磁盘、进程数、单命令 timeout 或 fuzz CPU-hours 达到 Goal Contract resourceBudget；
- 需要新增/升级 production dependency、运行未批准 install hook 或访问 network allowlist 外域名；
- 需要人类对竞品合作、名称、公共指控、争议或 GA 作决定。

BLOCKED 不是失败。Agent 应输出：

~~~yaml
blocker:
  fingerprint: ...
  phase: Pxx
  evidence: ...
  attempts:
    - hypothesis: ...
      result: ...
  decisionNeeded: ...
  options:
    - choice: A
      tradeoff: ...
  safeDefault: pause
~~~

禁止在相同失败上无限重写。用户处理 blocker 后使用 /goal resume，若目标本身变化则 /goal edit 或 /goal clear 后建立新目标。官方命令支持查看、编辑、暂停、恢复和清除 Goal：[Codex slash commands](https://developers.openai.com/codex/cli/slash-commands)。

所有 gate 默认断网。Research 只能访问 Goal Contract 批准的一手域名，保存 resolved URL、retrievedAt、digest、revision 和 license；dependency fetch 只能获取 support/dependency lock 中的精确 artifact。新增/升级 production dependency 和执行 package install hook 必须在 scope 中单独获批。

### 29.7 禁止假收敛

Agent 不得：

- 把 failing test 改为 skip、删掉或改成只断言不崩溃；
- 无 RFC 就减少 scenario denominator 或能力等级；
- 只靠 mock 宣称真实 SDK/client 完成；
- 更新 golden 而不展示语义 diff；
- 用 retry 隐藏 deterministic failure；
- 将 harness/driver crash 归到 endpoint；
- 为通过 secret scan 删除 scanner；
- 把未完成项移动到文档后仍声明 phase 完成；
- 以“不在本环境可测”为 pass；
- 创建大量 TODO 后用 compile success 当完成；
- 在人工 gate 未通过时进入下一 phase。

允许的 skip 必须是 contract 预先声明的 platform/capability 条件，报告 denominator 和原因。临时 waiver 必须由人批准并过期，但只改变“是否允许继续开发”，永远不把 FAIL/缺失条件改成 PASS。所有开发期 waiver 在最终 RC clock 开始时失效。

GA manifest 的每个 D30 criterion 都有 waivableAtGA，默认 false；本计划第 30 节现有条目全部 false。GA_READY 要求所有 D30 条目实际 PASS，known limitation 应通过准确缩小 Tier/scope 表达，不能用 waiver 维持更高声明。

### 29.8 九个 Coding Phase

这些是 Phase aggregate；一次 Goal 只实现下方一个 Work Unit。

Phase prerequisite chain 固定为 P00 → P01 → P02 → P03 → P04 → P05 → P06 → P07 → P08；前一 Phase 没有 CONVERGED transition，后一 Phase 不能激活。Phase 内 Work Unit 依其 contract DAG 串行；只有不写重叠路径的 research/review subagent 可以并行。

| Phase | 目标/关键产物 | MACHINE | EXTERNAL / TIME / HUMAN |
|---|---|---|---|
| P00 Validation & Bootstrap | 差异化、名称候选、corpus、RFC/ADR/AGENTS、真实 gate | 30 provenance candidates；尝试 20 且至少重现 16；10 deterministic replay；10 中至少 8 有 raw/client 双视图；至少 5 个缩减 30%；secret canary 零写盘；区分至少两类 fault domain；anti-placeholder gate tests | 人工发送竞品/上游联系；3 名独立维护者明确愿意评审/试用；go/no-go、名称、scope 批准 |
| P01 Contracts & Catalog | v1 candidate schemas、identity、canonicalization、Requirement/source | schema/compat fixtures；跨平台 digest；source drift/ambiguity gate | 独立 schema/规范审查 |
| P02 Kernel & Evidence | Engine、Intent/Resolved plan、recorder/redactor/CAS/replay/budget | transport/reference/fuzz；secret canary；hard budget；clean-checkout determinism | 隐私/安全设计审查 |
| P03 Core Protocol Conformance | Chat/Responses/Anthropic packs、pack-conforming reference/mutants、Codex base | 150+ unique scenarios；50 mutants；normative mutation 100%；历史 bug 10+ | Pack Maintainer 和外部协议 reviewer |
| P04 Client-observed Runtime | §6.1 全部 Tier 1 drivers/profiles/runtime adapters | support-manifest 全 matrix；sandbox；version lock；capture-layer correlation | 至少两个 design adopter 验证真实路径 |
| P05 Diagnosis & CI Product | attribution/minimizer/repro/report/baseline/GitHub Action | metric catalog 的 FP、preservation、reduction 门槛；report/CI contract | 5 个外部 CI adopter；15 个上游确认、其中 5 个修复/回归 |
| P06 Protocol Expansion | Google/MCP/Open Responses/Ollama native 等按 §6 Tier 2 | 每个声明 Tier 达到 requirement/reference/mutant/unknown-event gate | 各 Pack Maintainer review；不得把 Tier 2 伪装 stable |
| P07 Trusted Registry | signed observation、API/UI、runner/selfhost、hosted Matrix/dispute | pinned-oracle ingest、auth/SSRF/purge/restore/selfhost/project runner 安全 gate | 20 combinations、90% fresh、独立重跑；外部渗透/治理审查 |
| P08 GA Hardening | contract freeze、migration、release/docs/governance、RC | P00–P07 CONVERGED；除 D30-PHASE-STATUS、D30-GA-VOTE 外全部适用 MACHINE criteria PASS | 最终 contract digest 下两个 RC、完整 6 周；5 adopter 各至少 4 个不同周运行；TSC vote |

有序 Work Units：

| Phase | Work Units |
|---|---|
| P00 | B00（phase 外）candidate control plane；W01 approved gate validation；W02 competitor/design-partner research；W03 corpus/provenance；W04 risk-retirement experiments；W05 provisional RFC/threat/go-no-go evidence |
| P01 | W01 identity/schema primitives；W02 canonicalization/digests；W03 Requirement/source lock；W04 Pack compiler；W05 compatibility integration |
| P02 | W01 config/IntentPlan；W02 probe/ResolvedRunPlan/planner；W03 scheduler/hard budgets；W04 capture layers/recorder；W05 redactor/CAS/encryption；W06 replay/resume integration |
| P03 | W01 pack-conforming reference/mutant framework；W02 Chat pack；W03 Responses pack；W04 Anthropic pack；W05 Codex base；W06 historical/mutation completion |
| P04 | W01 Driver RPC/sandbox；W02 OpenAI Python/Node；W03 Anthropic Python/Node；W04 Vercel；W05 Codex；W06 OpenClaw/runtime adapters；W07 support matrix integration |
| P05 | W01 differential/attribution；W02 minimizer/repro；W03 reports/baseline；W04 GitHub integration；W05 frozen ground-truth/external validation |
| P06 | W01 Google generateContent；W02 Google Interactions；W03 MCP；W04 Open Responses/external/dialect/Ollama native adapters；W05 Tier integration |
| P07 | W01 observation/storage；W02 identity/signature/ownership；W03 ingest/quarantine/purge；W04 project-runner security；W05 API/UI/dispute；W06 selfhost/ops/recovery；W07 external security validation |
| P08 | W01 contract/migrations；W02 release/supply chain；W03 docs/governance；W04 RC/time/adopter evidence |

execution/product-stage-map.yaml 是第 24 节产品阶段到 Work Unit 的唯一机器可读 crosswalk；execution/impact-map.yaml 是路径/contract 对已收敛 Work Unit 的影响源。第 24、25、29、30 节摘要最终由 phase/support/metric/release-component manifests 生成并在 CI 检查 drift。

当前 release-components.yaml 将 core-cli、Tier 1 packs/profiles、self-hosted Registry、hosted Registry/Matrix，以及第 6.2 节 Google/MCP/Open Responses/Ollama native Tier 2 set 都列为项目 v1.0 required。若要拆成独立 GA train，必须先用范围 RFC 同时修改章程、P06/P07/P08 和第 30 节，不能在执行中临时把 blocker 变 optional。

Phase aggregate 不是 Work Unit。P08.W01–W04 完成后运行 P08 aggregate MACHINE gate；其 gate 不检查 P08 自身或最终 TSC vote。全部 MACHINE/EXTERNAL/TIME evidence 齐备后状态为 REVIEW_PENDING，D30-GA-VOTE 作为 Phase human gate；TSC attestation 把 P08 转为 CONVERGED。随后 make ga-gate 检查 P00–P08、D30 全部 criteria 和 vote attestation，才生成 GA_READY。任何 Work Unit 都不得包含自身 Phase aggregate 或最终 Phase approval。

### 29.9 每个 Work Unit 的建议 Goal

通用模板，保持小于 4,000 字符，细节引用文件：

~~~text
/goal 完成 execution/phase-state.yaml 中唯一 activeWorkUnit，且只完成该 Work Unit。

开始前读取 Plan.md、AGENTS.md、execution/phase-state.yaml 和
对应 phase/Work Unit contract、approval 与 impact-map。先验证前置 evidence，
不要假设它们完成，也不要从 READY 项中自行选择。

按 Goal Contract 的 inScope、outOfScope、deliverables 和 verification 工作。
每个 meaningful change 后运行最小相关测试；每个 checkpoint 追加 execution/progress.md。
不得降低 gate、删除失败测试、扩大 scope、使用真实副作用工具或执行外部发布。

只有该 Work Unit 的 Run A/Run B/evidence verification 和所有 MACHINE criteria
通过，才标记 MACHINE_CONVERGED；EXTERNAL/TIME/HUMAN 条件缺失时进入对应等待状态。
不要激活下一个 Work Unit，也不要运行 Phase aggregate gate，除非 contract 要求。

遇到 Plan.md 第 29.6 节任一条件，写入结构化 blocker 并暂停。
最终报告 activePhase/activeWorkUnit、source commit/diff、验证命令、evidence、
剩余 criteria、遗留风险和所需外部/人工决定。
~~~

不要让 Goal 自动选择“下一个 READY”。用户或受保护 workflow 在 evidence/approval 后显式执行 `doctor phase activate <phase> --unit <unit> --attestation <path>`，再启动：

~~~text
/goal 读取 Plan.md 和 execution/phase-state.yaml，只实现其中已经激活的
activeWorkUnit，直到它达到 MACHINE_CONVERGED、WAITING_EXTERNAL、
REVIEW_PENDING 或 BLOCKED。严格遵守 Plan.md 第 29 节；不得改变 activeWorkUnit。
~~~

用户/受保护 workflow 每次 gate 后激活下一 Work Unit；Phase 全部 units 完成后单独运行 aggregate gate。最终仍完成全部代码，但每个 Goal 都有确定边界。

### 29.10 Phase Gate 输出格式

make gate-unit UNIT=Pxx.Wyy 与 make gate PHASE=Pxx 使用同一 evidence envelope；Work Unit 输出必须生成：

~~~json
{
  "schemaVersion": "urn:agentapi-doctor:phase-gate:v1",
  "phase": "P03",
  "workUnit": "P03.W03",
  "planDigest": "sha256:...",
  "controlPlaneDigest": "sha256:...",
  "contractDigest": "sha256:...",
  "contractApprovalDigest": "sha256:...",
  "gateRunnerDigest": "sha256:...",
  "evaluatorSetDigest": "sha256:...",
  "metricDefinitionsDigest": "sha256:...",
  "dependencySetDigest": "sha256:...",
  "toolchainDigest": "sha256:...",
  "sourceCommit": "...",
  "verificationPairId": "019...",
  "verificationRuns": [
    {
      "label": "A",
      "environmentClass": "development-isolated",
      "environmentDigest": "sha256:...",
      "sourceCommit": "...",
      "controlPlaneDigest": "sha256:...",
      "dependencySetDigest": "sha256:...",
      "toolchainDigest": "sha256:...",
      "gateRunnerDigest": "sha256:...",
      "evaluatorSetDigest": "sha256:...",
      "sourceDirtyBeforeRun": false,
      "cleanCheckout": false,
      "startedAt": "...",
      "finishedAt": "...",
      "commands": [
        {
          "command": "make test-openai",
          "exitCode": 0,
          "durationMs": 12345,
          "summary": {"passed": 418, "failed": 0, "skipped": 0},
          "logDigest": "sha256:...",
          "artifactManifestDigest": "sha256:..."
        }
      ],
      "deterministicResultSetDigest": "sha256:...",
      "runEvidenceDigest": "sha256:..."
    },
    {
      "label": "B",
      "environmentClass": "clean-checkout-offline",
      "environmentDigest": "sha256:...",
      "sourceCommit": "...",
      "controlPlaneDigest": "sha256:...",
      "dependencySetDigest": "sha256:...",
      "toolchainDigest": "sha256:...",
      "gateRunnerDigest": "sha256:...",
      "evaluatorSetDigest": "sha256:...",
      "sourceDirtyBeforeRun": false,
      "cleanCheckout": true,
      "startedAt": "...",
      "finishedAt": "...",
      "commands": [
        {
          "command": "make test-openai",
          "exitCode": 0,
          "durationMs": 12567,
          "summary": {"passed": 418, "failed": 0, "skipped": 0},
          "logDigest": "sha256:...",
          "artifactManifestDigest": "sha256:..."
        }
      ],
      "deterministicResultSetDigest": "sha256:...",
      "runEvidenceDigest": "sha256:..."
    }
  ],
  "pairChecks": {
    "runAEvidenceDigest": "sha256:...",
    "runBEvidenceDigest": "sha256:...",
    "sameSourceCommit": true,
    "sameControlPlaneDigest": true,
    "sameDependencySetDigest": true,
    "sameToolchainDigest": true,
    "sameGateRunnerDigest": true,
    "sameEvaluatorSetDigest": true,
    "deterministicResultSetEqual": true,
    "verifierDigest": "sha256:...",
    "evidenceDigest": "sha256:..."
  },
  "metrics": [
    {
      "metricId": "normative_mutation_score",
      "value": 1.0,
      "numerator": 50,
      "denominator": 50,
      "minimumN": 50,
      "datasetDigest": "sha256:...",
      "evaluatorDigest": "sha256:...",
      "exclusions": []
    }
  ],
  "deliverables": [
    {
      "path": "...",
      "digest": "sha256:...",
      "validatorId": "validator://pack-artifact/v1",
      "assertions": ["schema-valid", "signature-valid", "requirements-linked"],
      "evidenceDigest": "sha256:..."
    }
  ],
  "criteria": [
    {
      "id": "p03-responses-machine",
      "kind": "MACHINE",
      "status": "pass",
      "evidenceDigest": "sha256:..."
    },
    {
      "id": "p03-pack-review",
      "kind": "HUMAN",
      "status": "pending"
    }
  ],
  "importedAttestations": [],
  "verdict": "MACHINE_CONVERGED"
}
~~~

Gate runner 先校验工作树；可接受的 Run A/B 都必须 `sourceDirtyBeforeRun=false`，Run B 还必须 `cleanCheckout=true`。`verificationPairId` 绑定且只绑定一组 A/B。phase-gate v1 schema 将每个 `verificationRuns[]` entry 定义为 RunEvidence；`runEvidenceDigest` 是移除该字段后，对完整 entry 做 RFC 8785 canonicalization 得到的 SHA-256。它因此覆盖 label、environment、source/control-plane/dependency/toolchain/gate/evaluator identities、cleanliness、时间、commands、logs、artifact manifests 与 deterministic result set。`toolchainDigest` 的 manifest 固定 Go/Python/Node runtime/compiler、build/test tools、OS/arch 与 OCI image digest；`dependencySetDigest` 只固定模块/package/OCI dependencies，二者不得互相代替。

独立 verifier 验证两个内联 RunEvidence 的 digest，并从其逐-run字段重算所有 `same*` 与 `deterministicResultSetEqual`；顶部 expected identities 也必须与 A、B 两项逐一相等，布尔值本身不是证据。任一 run 缺失、label 重复、source/control-plane/dependency/toolchain/gate/evaluator digest 不同、命令无 duration/summary/artifact digest 或 deterministic result set 不同，都拒绝 convergence。非确定的 started/finished/environment metadata 虽被 RunEvidence 签住，但不进入 deterministicResultSetDigest，因而不要求 A/B 相等。Gate 生成的 evidence 写入指定输出目录，不反向改变被验证 source tree；开发中可从 dirty tree 跑诊断 gate，但不能生成可接受的收敛证明。

避免“提交 evidence 又改变被验证 commit”的循环：

1. 将实现提交为 source commit C；
2. 在 C 的 clean checkout/worktree 运行 gate，输出到 repo 外的临时 artifact 目录；
3. evidence 的 sourceCommit 固定为 C，并签名/计算 digest；
4. 后续 evidence-only commit E 必须向 transitions/ 追加签名 StateTransition（状态改变时）或 EvidenceAttachment（只追加证据时），更新 evidence index，再由 state-verify 重新生成 phase-state；完整日志由 CI artifact/CAS 保存；
5. E 只允许新增上述 hash-chained event、evidence index 和生成的 phase-state view，不得直接手改 view，也不得包含实现、schema、fixture、依赖、build 或任何 control-plane manifest/lock 变化；
6. 若有任何此类变化，产生新 source commit C2 并重新运行全部收敛 gate。

evidence-verify 必须从原始 result/corpus 重算所有 metrics 和 criteria；拒绝未知 evaluator、手填 numerator/denominator、缺失 log、不可解析 attestation、只验证文件存在、contract/gate digest 未批准或 dataset 样本不足。EXTERNAL/TIME/HUMAN status 只能来自各自 schema 的签名 attestation，make gate 不得自行制造。

`doctor phase state-verify`、phase aggregate 和 `doctor phase ga-gate --output <directory>` 都拒绝未获独立 approval 的 controlPlaneDigest；生成文档与 control-plane manifest 不一致也直接失败。

### 29.11 人工 Gate Checklist

人工 reviewer 只需回答：

- 这个 Work Unit/Phase aggregate 是否真的解决 Goal Contract 的用户问题？
- 规范解释是否有一手来源，是否把歧义当成确定事实？
- 测试是否能抓住有意义的 mutant，而非只覆盖代码？
- 报告是否正确区分 wire/model/client/harness？
- 是否泄露 secret/私有内容或扩大攻击面？
- 是否引入未讨论的 public contract/依赖/运维负担？
- clean-checkout evidence 是否可信？
- known limitation 是否诚实且可接受？

批准后 reviewer 生成 commit-bound approval attestation，包含 reviewer identity、角色/组织、source commit、contract/evidence digest、timestamp、利益冲突声明和签名；受保护 workflow 验签后追加 StateTransition，再由 state-verify 生成 phase-state，Agent 不能直接写入批准或派生 view。

impact-map 将代码、依赖、schema、fixture、gate/evaluator、metric、security boundary、observable behavior 和 docs contract 路径映射到 Work Unit。后续 diff 命中已收敛 unit 时自动标记 REJECTED/reopen，并使下游 evidence stale；不能只在 public behavior 改动时才重开。纯拼写修复可以由 impact evaluator 判定无需重跑，但仍保存理由。

### 29.12 与官方 Codex 工作方式的对应

本协议落实官方建议：

- prompt 包含 Goal、Context、Constraints、Done when：[Codex best practices](https://developers.openai.com/codex/learn/best-practices)；
- AGENTS.md 自动提供仓库级持久指导，并允许目录级覆盖：[AGENTS.md 指南](https://developers.openai.com/codex/guides/agents-md)；
- Goal 使用单一 objective/stopping condition、验证命令、checkpoint 与 progress log：[Follow a goal](https://developers.openai.com/codex/use-cases/follow-goals)；
- 难题使用机器可读 eval、每次迭代记录指标并显式停止：[Iterate on difficult problems](https://developers.openai.com/codex/use-cases/iterate-on-difficult-problems)。

本项目的 gate JSON、mutation score、历史 bug corpus 和 clean-checkout commands 就是 Goal mode 的 eval system。

---

## 30. v1.0 Definition of Done

GA checklist 是项目级最终收敛条件。ga-criteria.yaml 为每一项分配稳定 D30 ID、kind、evaluator、evidence schema 和 waivableAtGA=false；本节由它生成。每一项必须链接到 commit、gate JSON、report、审查记录或公开 adopter，不能只勾选文字。

### 30.1 产品与协议

- [ ] OpenAI Chat Completions、OpenAI Responses、Anthropic Messages 达到 Tier 1；
- [ ] Codex Responses profile 严格通过，明确不以 Chat fallback 代替；
- [ ] release-components required 的 Google generateContent/Interactions、MCP、Open Responses adapter、Ollama native/OpenClaw profile 全部达到第 6.2/6.5 节 Tier 2 gate，并准确标注限制；
- [ ] 至少 250 个 normative/high-value scenarios；
- [ ] 至少 50 个 targeted protocol mutants，关键 normative mutation score 100%；
- [ ] 至少 30 个有 provenance 的历史故障 fixture；
- [ ] 所有 normative assertion 都有一手来源、revision、scope 与 ambiguity 状态；
- [ ] stream/non-stream、parallel tools、state、structured output、usage/error/cancel 核心 taxonomy 覆盖；
- [ ] core strict 与 extension/dialect 结果分开；
- [ ] 不以模型回答质量替代 wire/protocol conformance。

### 30.2 Client-observed 能力

- [ ] §6.1 全部 Tier 1 cells 达成：至少 8 个受支持 Driver identity；
- [ ] 至少 7 个 Tier 1 SDK/Agent profiles，并全部绑定精确 support lock；
- [ ] 至少 Python、Node 两个官方 SDK 生态；
- [ ] Codex、Vercel AI SDK 等真实客户端在 nightly matrix；
- [ ] vLLM、llama.cpp、Ollama、SGLang、LiteLLM 五个 runtime metadata adapters 有 contract test；
- [ ] 每个 Driver 精确记录 runtime、package、lockfile/image digest；
- [ ] capture-layer application evidence 与 client observation 可相关但不互相覆盖；
- [ ] Driver conformance kit 和第三方作者文档完整；
- [ ] previous/current 两个精确受支持版本、candidate canary 和 deprecation policy 可查，并与 support lock 一致。

### 30.3 诊断质量

- [ ] 第 3.1 节 transport、wire、protocol、model、client、harness、unknown fault families 与细粒度 fault_domain 可独立表达且映射可验证；
- [ ] ground-truth 数据集上错误归因 false positive 低于 3%；
- [ ] 同一 ground-truth 集的归因 decision coverage 整体至少 80%、每类至少 60%；
- [ ] 证据不足时稳定输出 unknown 和 alternatives；
- [ ] 90% 历史失败在最小化后保持 fingerprint；
- [ ] 最小化中位缩减至少 50%；
- [ ] curl/Python/Node/client-specific repro 在 clean container 可运行；
- [ ] Issue Bundle 默认脱敏并包含规范依据、版本与最小 evidence；
- [ ] 同一合法 evidence + oracle/core/pack digest 的 deterministic verdict JSON 重算一致率 100%；任何不一致都是 defect。

### 30.4 CLI、Schema 与开发者体验

- [ ] CLI/config/exit codes/result schema/Driver RPC/Registry API v1 冻结；
- [ ] doctor init → target → test → report → repro 的完整路径有 e2e；
- [ ] plan-only、budget、interrupt、resume、offline、proxy、enterprise CA 可用；
- [ ] terminal、JSON、JUnit、SARIF、Markdown、offline HTML 从同一 result model 生成；
- [ ] 全部已发布稳定 v1 artifact/schema 可读；`schemas/migration-floor.yaml` 指定的 pre-1.0 corpus 可读或可迁移；从 v2 起当前与前一稳定 major 可读或可迁移；
- [ ] 所有错误有 failure ID、evidence pointer 和可执行下一步；
- [ ] Linux/macOS/Windows amd64/arm64 发布和 clean install；
- [ ] Quickstart 在 15 分钟内完成 smoke，在 30 分钟内生成一次最小 repro。

### 30.5 工程质量

- [ ] D30-PHASE-STATUS：P00–P08 全部 CONVERGED；
- [ ] make gate-all 和 clean-checkout gate 连续通过；
- [ ] unit/golden/property/contract/reference/mutation/historical/e2e 层齐全；
- [ ] Go race/staticcheck/govulncheck/lint、Python/Node lint/type/test 全过；
- [ ] 核心 deterministic suite flaky 低于 0.1%；
- [ ] 没有无 owner、无期限的 quarantine；
- [ ] 性能预算建立基线，无未解释超过 20% 回退；
- [ ] parser/redactor/archive/stream fuzz 达到记录的 CPU-hour/iteration 门槛；
- [ ] 关键 package 行覆盖至少 85%，同时以 mutation/behavior gate 防止虚高；
- [ ] 支持矩阵、generated schema/docs 与代码无 drift。

### 30.6 安全与隐私

- [ ] Threat Model、Data Policy、SECURITY.md 完整并外部审查；
- [ ] 无开放高危漏洞，中危有 owner/期限；
- [ ] strict capture 写盘前脱敏，secret canary 全链路测试通过；
- [ ] 公共 Registry SSRF、DNS rebinding、redirect、archive、XSS、quota 测试通过；
- [ ] Driver sandbox/env/path/process/network 控制通过 adversarial test；
- [ ] 真实工具副作用默认不可执行；
- [ ] fork PR 无 secret/写权限；
- [ ] dependency 固定、SBOM、SLSA provenance、Sigstore release；
- [ ] incident、secret exposure、malicious artifact、data withdrawal runbook 演练；
- [ ] 独立 Registry 渗透测试完成并关闭高危。

### 30.7 Registry

- [ ] observation/attestation schema 稳定且不可变；
- [ ] Local/Self-reported/Owner-verified/Independently reproduced/Project-operated-run 标签与第 19.4 节完全一致；
- [ ] freshness、denominator、config/profile/pack digest 始终显示；
- [ ] 20+ 版本/配置/client observations；
- [ ] 至少 90% hosted observations 在 freshness window；
- [ ] 独立整次重跑 verdict 一致率至少 95%；
- [ ] ownership、two-phase ingest、signature、quarantine、re-evaluation 工作；
- [ ] dispute、supersede、tombstone、owner response 完整演练；
- [ ] Docker Compose self-host 可从空环境启动；
- [ ] RPO/RTO 恢复演练通过；
- [ ] Web 无默认单一总分、无“官方认证”误导。

### 30.8 社区与治理

- [ ] 至少 3 名可发布 maintainer，来自至少 3 个独立组织/雇主；
- [ ] Pack/Core/Registry/Security 权限分离；
- [ ] 至少 5 个外部 repo 在最终 6 周 RC window 内，各自至少 4 个不同周产生可验证 CI run；
- [ ] 至少 15 个上游确认 finding，5 个产生 merged fix/regression；
- [ ] 至少 5 名外部 contributor 提交 fixture/pack/driver/docs；
- [ ] Governance、DCO、CoC、Security、Support、Release、Data、Trademark 完整；
- [ ] TSC/COI/vendor capture/赞助/争议规则实际可执行；
- [ ] 两名非作者 reviewer 复核 GA evidence；
- [ ] D30-GA-VOTE：无利益冲突的 TSC 按 Governance 批准最终 contract/evidence digest；
- [ ] Bus factor、issue response 和 release rotation 达标；
- [ ] OpenSSF Best Practices badge 申请或完成，未完成项有公开说明。

### 30.9 文档与发布

- [ ] 英文规范文档和中文核心指南；
- [ ] 架构、packs、profiles、driver authoring、Registry、自托管、安全、迁移齐全；
- [ ] 每个示例在 CI 中执行，不含真实 key；
- [ ] 60 秒真实 demo 和 5 个公开 case studies；
- [ ] honest competitor comparison 和非目标清楚；
- [ ] 最终 public-contract digest 下 RC 至少完整 6 周、至少两个 RC；任何 breaking CLI/schema/RPC/API/config 变化将 clock 清零；
- [ ] release artifacts、checksums、SBOM、provenance、signature 可从公开入口验证；
- [ ] upgrade/downgrade、rollback、旧 report reader 测试通过；
- [ ] changelog、migration、known issues、support window 发布；
- [ ] ADOPTERS 中项目同意被列出。

### 30.10 GA 无 Waiver

所有第 30 节 criteria 都必须实际 PASS；开发期 waiver 在 RC 前失效，且不计作 PASS。以下是尤其不可通过缩 scope 以外方式绕过的绝对项：

- 开放高危安全问题；
- 已知 secret/私有内容泄露路径；
- normative assertion 无来源；
- 通过删除/skip 测试获得的 gate；
- result/observation digest 不稳定；
- 不可读取刚发布的前一版本 artifact；
- 只有一人拥有发布或 Registry 恢复能力；
- 公共结果没有 dispute/撤敏能力；
- core strict 与 dialect adapter 混分；
- 关键 client profile 仅 mock、未跑真实客户端；
- false positive 超过目标且仍公开作确定结论。

### 30.11 项目最终状态

项目级状态只有：

- GA_READY：P00–P08 CONVERGED，全部 D30 criteria PASS，最终 digest 的 RC window 完成，make ga-gate 通过；
- BLOCKED：有明确 blocker、owner、选项和恢复条件；
- PIVOT_REQUIRED：命中第 27 节停止条件；
- GA_RELEASED：TSC 人工批准并完成签名发布验证。

“代码很多”“所有 issue 都关闭”“Goal 运行很久”都不是完成状态。

---

## 31. 前 90 天执行计划

前 90 天的目标不是发布半成熟 v0.1，而是收敛 P00、完成 P01 大部，并把最高风险的技术假设变成证据。

### 第 1–2 周：战略与仓库基线

输出：

- 建仓仅用工作名，不抢先公开宣传；
- 导入 Plan.md，建立 AGENTS.md 和 execution 状态；
- 建 LICENSE/DCO/Governance/Security/Data/Contributing；
- 建 COMPETITIVE-LANDSCAPE 与直接竞品联系 issue/email 草稿；
- 完成 5 个 design-partner 访谈问题；
- 建 RFC/ADR 模板、issue/PR 模板；
- 实现 make bootstrap、make gate PHASE=P00 的非伪造框架。

收敛：

- [EXTERNAL P00-X-CROSSPLATFORM] 受保护 CI 在 Linux/macOS/Windows 执行 bootstrap；
- [MACHINE P00-M-DOCS] 所有文档链接和 license check 通过；
- [EXTERNAL P00-X-OUTREACH] 竞品联系由人审核后发送并保存非敏感凭证；
- [HUMAN P00-H-CONTROL] P00.B00 candidate control plane/gate 被锁定，workflow 激活 P00.W01；aggregate contract 保持 provisional；
- [HUMAN P00-H-NO-PUBLIC-CLAIM] 确认尚未创建公开兼容性声明。

### 第 3–4 周：故障 Corpus

输出：

- 收集 30 个一手 issue；
- 选择 20 个代表 streaming/tools/state/client 的样本；
- 写 provenance/license/redaction metadata；
- 人工或容器重现，记录 raw symptom 和 ground truth；
- 将可公开内容重写为最小合成 fixture；
- 建 failure taxonomy 与 fingerprint 初稿。

收敛：

- [MACHINE P00-M-REPRO] 20 个样本中至少 16 个可重现；
- [MACHINE P00-M-TAXONOMY] evaluator 消费已裁决 ground truth，为每个样本给 fault domain 或 unknown；
- [MACHINE P00-M-REPLAY] 至少 10 个能用 controlled fixture 稳定重放；
- [HUMAN P00-H-CORPUS-RIGHTS] provenance review 确认无私有日志或无权复制内容。

### 第 5–6 周：风险退休实验

只验证四个高风险点：

1. 明确 capture layer、不会修复语义的 SSE application recorder；
2. Responses typed event FSM；
3. SDK 经本地 forward proxy 的 raw/client correlation；
4. 多工具 delta 最小化后是否仍触发真实 SDK failure。

收敛：

- [MACHINE P00-M-DUAL-VIEW] 10 个 corpus cases 中至少 8 个产出 capture-layer + client 双视图；
- [MACHINE P00-M-REDUCTION] 至少 5 个失败自动缩小 30% 以上并保留 fingerprint；
- [MACHINE P00-M-SECRET] secret canary 零持久化；
- [MACHINE P00-M-UNKNOWN] 不充分 evidence 稳定输出 unknown；
- [HUMAN P00-H-SPIKE-ADR] reviewer 批准实验保留/重写/删除 ADR。

### 第 7–8 周：P00 Gate 与 Go/No-Go

输出：

- RFC-0001 至 RFC-0005 初稿；
- Threat Model/Data Policy v1；
- 三个名称候选与冲突检查；
- 竞品合作结果和独立项目决策；
- P00 clean-checkout evidence；
- 外部 reviewer 反馈。

收敛：

- [MACHINE P00-M-AGGREGATE] make gate PHASE=P00 通过并覆盖第 29.8 节全部 MACHINE criteria；
- [EXTERNAL P00-X-REVIEW] 外部 reviewer feedback 已导入并验签/记录；
- [EXTERNAL P00-X-DESIGN-PARTNERS] 至少 3 位独立外部维护者明确愿意继续试用/评审；
- [HUMAN P00-H-GO-NOGO] 人工决定 CONVERGED、BLOCKED 或 PIVOT_REQUIRED。

若 P00 不收敛，不因为已经写了代码就进入 P01。

### 第 9–10 周：P01 Schema 核心

输出：

- IntentPlan、ResolvedRunPlan、Result、Evidence、Pack、Profile schema；
- canonical JSON 与 digest；
- positive/negative/additive-unknown fixtures；
- public contract version policy；
- source/requirement catalog 最小可用实现。

收敛：

- [EXTERNAL P01-X-DIGEST] 受保护三平台 CI 的 digest 一致；
- [MACHINE P01-M-SCHEMA] schema compatibility suite 通过；
- [MACHINE P01-M-OLD-READER] 旧 reader 面对允许的 additive fields 正常；
- [MACHINE P01-M-DIGEST-SENSITIVITY] immutable projection 字段改动改变 digest；
- [MACHINE P01-M-REQUIREMENT-LINK] CI 能阻止无来源 normative assertion。

### 第 11–12 周：P01 Compiler 与 Source Drift

输出：

- YAML/JSON Schema/CEL pack compiler；
- dependency/capability/budget 编译；
- source snapshot metadata、revision/diff PR；
- ambiguity note workflow；
- generated schema/reference docs；
- make gate PHASE=P01 candidate。

收敛：

- [EXTERNAL P01-X-PACK-DIGEST] 相同 pack 在受保护跨平台 CI digest 一致；
- [MACHINE P01-M-DSL-ERROR] invalid DSL 有精确路径和错误；
- [MACHINE P01-M-SOURCE-DRIFT] source drift 只生成候选，不自动修改 verdict；
- [MACHINE P01-M-COMPILE] pack-conforming sample 编译并生成 Intent/Resolved plan；
- [EXTERNAL P01-X-PROTOCOL-REVIEW] schema/pack 外部 review 已发起；完成前 P01 保持 WAITING_EXTERNAL。

### 第 13 周缓冲

只用于：

- 修复 gate/审查问题；
- 完成 clean-checkout；
- 形成下一季度 P02 Phase aggregate 与首批 Work Unit Contracts；
- 发布阶段性研究/corpus，而非谎称 product GA。

90 天 Review 必须回答：

- 独立项目仍比合作更有价值吗？
- 已重现问题中，Doctor 比现有 tester 多发现了什么？
- 用户最需要的是 conformance、client profile、minimizer 还是 Registry？
- 规范/隐私/运维哪项是最大 blocker？
- 人力与采用信号是否支持 P02–P08？

---

## 32. 技术决策与 ADR 锁定点

以下是推荐默认；对应 phase 开始前用短 spike 验证并写 ADR。不要在 Goal 中反复更换基础技术。

| 决策 | 推荐默认 | 验证标准 | 最迟锁定 |
|---|---|---|---|
| Go toolchain | 开工时当前 stable，go.mod/CI 固定 | 三平台、race、静态 binary、依赖安全 | P00 |
| CLI | Cobra/pflag 或等价成熟库；业务逻辑不依赖 CLI | completion、稳定 errors/exit、测试注入 | P01 |
| Config | YAML 输入，规范化 JSON model；JSON Schema 2020-12 | merge/secret ref/migration/unknown field | P01 |
| Assertion | CEL-Go + 受限 builtin oracle | type check、预算、无任意 I/O | P01 |
| HTTP/SSE | Go net/http + 自有有界 SSE parser | capture-layer fidelity、cancel、proxy/rechunk、fuzz | P02 |
| 本地索引 | pure-Go SQLite，仅为可重建 index | 跨平台、无 CGO 分发问题 | P02 |
| 内容存储 | SHA-256 CAS + zstd chunks | streaming、dedupe、corruption recovery | P02 |
| Driver RPC | JSON-RPC 2.0 semantics over NDJSON stdio | cancel/capability/error/version conformance | P01 |
| Python runner | uv/lock + OCI image | deterministic install、offline cache、digest | P04 |
| Node runner | pnpm/corepack lock + OCI image | deterministic install、SDK matrix | P04 |
| Registry DB | PostgreSQL；Go pgx/sqlc 风格 | migrations、transaction、backup/restore | P07 |
| Blob/OCI | S3-compatible + OCI/ORAS | content address、signature、self-host | P07 |
| Registry UI | 静态优先，最少客户端 JS | CSP、accessibility、CDN/offline snapshot | P07 |
| Auth | OIDC，GitHub 作为首个 issuer | ownership、短期 token、audit | P07 |
| Provenance | in-toto + Sigstore，canonical JSON RFC 8785 | offline verify、OIDC、revocation handling | P07 |
| Observability | slog + optional OpenTelemetry | payload-free default、trace correlation | P02 |
| Build entrypoint | Makefile 薄入口调用版本化 Go/scripts | 本地/CI 同一命令，无平台 shell 陷阱 | P00 |

明确不采用：

- Go in-process plugin/shared object；
- 在 Pack 中执行任意 Python/JavaScript；
- GraphQL 作为首个 Registry API；
- 为了“云原生”在无人需要时先建 Kubernetes operator；
- 将大模型 judge 用作 normative protocol oracle；
- 用浏览器自动化替代 wire/client evidence；
- 把公开 Registry 作为本地测试的必需依赖。

### 32.1 必须提前写的 ADR

~~~text
ADR-0001 Core language and binary distribution
ADR-0002 Canonical JSON and digest boundaries
ADR-0003 Raw wire vs provider-neutral IR
ADR-0004 Scenario DSL and CEL sandbox
ADR-0005 Driver process and isolation
ADR-0006 Secret references and write-before-redact prohibition
ADR-0007 Local CAS and evidence manifest
ADR-0008 Pack/Profile versioning
ADR-0009 Result dimension and no-single-score
ADR-0010 Registry trust and attestation
ADR-0011 Source snapshot and copyright policy
ADR-0012 Goal phase gate and evidence format
~~~

ADR 记录 alternatives 和 consequences；如果 spike 否决推荐默认，更新 Plan 对应段落，不能只在代码里形成事实。

---

## 33. 规范与生态更新机制

该计划调研基线是 2026-07-10，而实现周期可能超过一年。任何 protocol phase 开始和 RC 冻结前必须重新核验一手来源：

sources.lock.yaml 是时效性外部事实的机器可读索引。每条记录包含 claimId、sourceType、originalURL、resolvedURL、retrievedAt、commit/tag/API revision、content digest、license/reuse status、引用的 Requirement/Plan section，以及重新核验触发器。文档链接只是人类入口，gate 使用 lock digest。

| 领域 | 当前基线 | 必查来源 |
|---|---|---|
| OpenAI Responses | 新 Agent 集成主方向，typed items/state/events | [Responses migration](https://developers.openai.com/api/docs/guides/migrate-to-responses)、[Function calling](https://developers.openai.com/api/docs/guides/function-calling)、[Streaming](https://developers.openai.com/api/docs/guides/streaming-responses) |
| Codex custom provider | wire_api 仅 Responses；可选 WebSocket 能力单列 | [Codex config reference](https://developers.openai.com/codex/config-reference)、[Advanced config](https://developers.openai.com/codex/config-advanced) |
| OpenAI schema | 官方 OpenAPI 不是完整行为规范 | [openai-openapi](https://github.com/openai/openai-openapi) |
| Anthropic Messages | version header、content blocks、tool lifecycle、SSE unknown events | [Streaming](https://platform.claude.com/docs/en/build-with-claude/streaming)、[Tool use](https://platform.claude.com/docs/en/agents-and-tools/tool-use/overview) |
| Google | generateContent 与 Interactions 分开，确认当时推荐路径 | [Function calling](https://ai.google.dev/gemini-api/docs/function-calling)、[Streaming](https://ai.google.dev/gemini-api/docs/streaming) |
| MCP | 当前 normative stable revision 2025-11-25 | [MCP specification](https://modelcontextprotocol.io/specification/2025-11-25) |
| 开放 conformance 研究 | wire format corpus 缺口与 Open Responses | [LLM-Rosetta](https://arxiv.org/html/2604.09360v1)、[Open Responses](https://github.com/openresponses/openresponses) |
| 竞品 | 功能、license、governance、采用变化 | [am-i-openai-compatible](https://github.com/heiervang-technologies/am-i-openai-compatible)、[octest](https://github.com/ibidathoillah/openai-compatible-tester-cli)、[FauxpenAI](https://github.com/aliok/FauxpenAI-conformance) |

更新流程：

1. source bot 只创建 diff 和候选 issue；
2. Pack Maintainer 判断 normative/additive/clarification/breaking；
3. ambiguity 先记录，不立即改变 verdict；
4. scenario/reference/mutant/migration 同一 PR；
5. 发布新不可变 pack，不覆盖旧 digest；
6. Registry 将旧 observation 标注旧 pack，不伪装成 endpoint regression；
7. client SDK release 由 driver matrix 验证后再改支持范围。

OpenAI Assistants 的既定 sunset 是 2026-08-26：[OpenAI API Deprecations](https://developers.openai.com/api/docs/deprecations)。除非有明确 adopter 需求，不投入首个稳定版；到实施时再次核验官方状态。

---

## 34. 从本计划启动实现

### 34.1 第一次运行前

1. 新建本地 Git 仓库，暂用工作名；
2. 将本 Plan.md 放在根目录；
3. 让 Codex 在 Plan mode 只审查当前环境、缺失决策和 P00.B00 bootstrap candidate，不写产品实现；
4. 人工确认名称暂用、License、外部沟通和权限；
5. 创建 AGENTS.md 与 execution 文件；
6. 启动第一个 Goal；
7. P00 人工 gate 前不创建公开 Registry、不发布兼容结论。

若 /goal 不可用，可按官方说明启用 goals feature；使用 /goal 查看状态，/goal pause、resume、edit、clear 控制长任务。[Follow a goal](https://developers.openai.com/codex/use-cases/follow-goals)

### 34.2 第一个可复制 Goal

~~~text
/goal 完成 phase 外的 P00.B00 Bootstrap Contract and Gate Candidate，直到 approval request
完整或触发结构化 BLOCKED；不要尝试让整个 P00 自我收敛。

先完整读取 Plan.md，再创建简洁 AGENTS.md、P00 aggregate/work-unit candidate
contracts、metrics/impact/product-stage manifests、
真实 gate runner skeleton 和 anti-placeholder meta-tests。

遵守 Plan.md 第 29 节：不得批准自己的 contract/gate，不得填写 reviewer identity，
不得生成有效 P00 completion evidence。测试断网；不新增未批准 production dependency；
不公开发布、不代表我联系外部项目。

完成后写 approval-requests/P00.B00，列出 control-plane/contract/gate/evaluator/catalog
digests、anti-placeholder 测试、diff 和我需要批准的内容，然后停止。Genesis 前不得
创建 execution/phase-state.yaml、execution/transitions/*、普通 StateTransition，
也不得激活 P00.W01；approval request 的 pending 仅是请求属性，不是 phase 状态。
~~~

### 34.3 后续 Goal

每次人工/受保护 workflow 批准并显式激活一个 Work Unit 后：

~~~text
/goal 读取 Plan.md、execution/phase-state.yaml、已批准 contract 和 impact-map，
仅实现唯一 activeWorkUnit。严格执行资源/网络/验证/收敛条件；达到
MACHINE_CONVERGED、WAITING_EXTERNAL、REVIEW_PENDING 或 BLOCKED 就停止。
不得选择 READY 项、修改 approval 或激活下一个 Work Unit。
~~~

### 34.4 权限边界

Goal 默认授权：

- 读取和修改当前仓库；
- 运行本地 build/test/lint/fuzz 的有界版本；
- 仅按当前 Goal Contract allowlist 检索公开一手规范，或获取 lockfile 中的固定依赖；
- 创建本地 commit 候选和报告。

Goal 默认不授权：

- 创建/删除远端 repo；
- push、开 PR、发 Issue/评论/邮件；
- 发布 package、OCI、release、网站；
- 使用生产密钥或付费 provider；
- 修改组织权限、DNS、云资源；
- 上传本地 artifact；
- 宣布某厂商兼容/不兼容。

这些需要用户单独批准，不因“完成完整项目”的 Goal 自动扩大。

### 34.5 完成完整项目的安全方式

~~~text
P00 人工 go
→ P01 contract review
→ P02 privacy/security review
→ P03 pack review
→ P04 adopter validation
→ P05 upstream validation
→ P06 protocol reviews
→ P07 external security/governance review
→ P08 RC/GA vote
~~~

每个箭头都由 evidence 驱动。若某阶段 BLOCKED，解决 blocker 后 resume；若 Plan 改变则 edit/clear Goal 并重新计算受影响 phase。这样 Codex 可以承担绝大多数实现、测试、修复和文档工作，同时不会把数月工程退化成一个无法判断结束的长 prompt。

---

## 35. 最终验收结论

AgentAPI Doctor 值得实现的前提，不是“市面上没有兼容性 tester”，而是它能稳定做到现有工具没有同时做到的四件事：

1. 一手规范可追溯的多协议 conformance；
2. capture-layer application evidence 与真实 SDK/Agent client 双重观测；
3. 自动故障域定位、最小复现和上游回归；
4. 签名、不可变、可申诉、带新鲜度的公共 observations。

项目在 P00–P08 全部收敛、第 30 节 DoD 完成并经过 RC 后才是成熟 v1.0。在此之前，每个 release 都诚实标注支持层级和已知限制。若需求或差异化门禁失败，应把高质量 pack、fixture、minimizer 或 corpus 贡献给现有生态；解决社区问题优先于维持一个独立品牌。

---

## 附录 A：最低 Public Contract

本附录不是最终 JSON Schema，但字段、关系、状态和 digest boundary 是 P01 的最低输入。P01 可以增加字段，不能在无 RFC 情况下改变这里的语义。

### A.1 全局 Envelope 与 ID

所有不可变对象共有：

| 字段 | 必需 | 规则 |
|---|---|---|
| schema_version | 是 | provisional URN，P00 最终命名后锁定 |
| kind | 是 | versioned object kind |
| instance_id | 视对象 | Run/Invocation/Attempt 使用 UUIDv7 或 ULID，表示一次实例 |
| content_digest | 是 | 对 immutable projection 的 sha256 |
| object_ref | 是 | kind + optional instance_id + content_digest |
| producer | 是 | name、version、artifact_digest |
| created_at | 是 | UTC、规范 RFC3339；不进入某些语义 digest 时要明确 |
| extensions | 否 | namespace-keyed object；未知 extension 不得改变 core 解释 |

ID 关系：

~~~text
intent_plan_id
  └── resolved_plan_id
        └── run_id
              ├── invocation_id
              │     └── attempt_id
              │           ├── evidence_id*
              │           └── assertion_result_id*
              │                   └── finding_id?
              └── result_bundle_id
                    └── observation_id?

observation_class_id → observation_id*
~~~

不变量：

- instance_id 在生成后不可修改/复用；相同内容的两个 Run 仍是两个实例；
- content_digest 只标识不可变内容，相同 projection 可以相同；
- Observation/Evidence/Pack 等内容寻址对象可以把 digest 作为其 domain ID；Run/Invocation/Attempt 必须同时有随机 instance ID 和 content digest；
- human-readable name 不作 identity；
- 所有 child 引用父 ID 和 digest，防止同 ID 换内容；
- signed projection 明确排除自身 ID、签名和 Registry 派生字段；
- JSON 先做 schema/type 检查，再 RFC 8785 canonicalization；
- 重复 key、非有限 number、超范围整数、非法 Unicode、模糊时间直接拒绝；
- secret 永不进入 ID projection；低熵敏感内容不做公开普通 hash。

### A.2 IntentPlan 与 ResolvedRunPlan

IntentPlan required：

| 组 | 字段 |
|---|---|
| Identity | intent_plan_id/digest、schema、producer、config_digest |
| Target intent | target logical ref、protocol family、identity expectation；不含 secret |
| Selection | requested pack/profile selectors、support_manifest_digest、candidate denominator digest |
| Probe | 允许的 operation、request/byte/time budget、network/side-effect policy |
| Conditional scope | 预先允许的 capability branches 和每个 branch 的 scenario set |
| Budget | hard、reservation、cleanup budget |
| Evidence | capture mode、redaction/publication policy |
| Safety | allowed target origin、redirect、tool side-effect、driver permission |
| Approval | author、approval/evidence requirement；签名在 envelope 外 |

IntentPlan 不包含 probe 结果，不允许 floating latest，不允许任意“发现后再决定”的 branch。

ResolvedRunPlan required：

| 组 | 字段 |
|---|---|
| Parent | intent_plan_id/digest |
| Resolution | resolver version/digest、CapabilityObservation digests、support lock digest |
| Exact artifacts | core、oracle、pack、profile、driver、fixture、schema exact version/digest |
| Target | identity_level、version/config/model/region/observed fingerprint |
| Scenarios | ordered scenario IDs、dependency DAG、driver、attempt policy |
| Decision | 每个 scenario 的 execute/skip/not_applicable、reason_code |
| Denominator | exact requirement/scenario denominator digest |
| Budget | allocated/reserved hard/advisory/cleanup budget |
| Runtime policy | concurrency、retry、timeout、capture layer、sandbox、network |
| Finalizer | ResourceLease/finalizer plan |

不变量：

- execution 只接受 exact ResolvedRunPlan digest；
- Resolver 只能选择 IntentPlan 预先允许的 branch；
- CapabilityObservation 或 resolver digest 改变就产生新 plan；
- skip/not_applicable 必须有 reason 和 denominator treatment；
- 运行中不能增加 scenario、driver 权限、预算或 target；
- 实际 target 响应 identity 与计划不同要产生 drift finding。

### A.3 RunManifest 与 Journal

RunManifest required：

- run_id、intent/resolved plan ID/digest；
- lifecycle status 和 reason_code；
- started/finished monotonic + UTC envelope；
- Core/OS/arch/toolchain/container digests；
- target observed identity/fingerprint；
- invocation/attempt IDs；
- artifact manifest root digest；
- budget reserved/consumed/unknown/overshoot；
- capture/redaction/encryption/publication policy；
- acquired/released/residual ResourceLease；
- error/finding/result summary；
- attestation/signature refs。

Run lifecycle：

~~~text
planned
→ running
→ completed | cancelled | errored
~~~

Journal append-only；每条 event 有 sequence、previous_event_digest、time 和 payload digest。Resume 读取 journal，不能把旧 attempt 改成成功；未完成 invocation 创建新 attempt。Manifest 是 journal 的确定性 projection，可重建并校验。

### A.4 Evidence / AAWire

Evidence required：

| 字段 | 规则 |
|---|---|
| evidence_id | sanitized persisted projection digest |
| run/invocation/attempt ID | 必须关联 |
| sequence | 同 capture layer 单调、无重复 |
| capture_layer | 第 12.1 节四种之一 |
| instrumentation_mode | direct/proxy/fixture/client-native |
| direction/kind | versioned enum |
| monotonic offset | 相对 Run 起点，不参与跨主机绝对比较 |
| byte/event offset | 仅在相同 capture layer 有意义 |
| payload_ref/digest | 指向脱敏 CAS；无 payload 时说明 unavailable reason |
| redactions | rule ID、field class、count，不存原值 |
| relations | parent item/call/stream/evidence IDs |

不变量：

- recorder 不跨 capture layer 冒充同一 chunk；
- payload digest 与 CAS 内容一致；
- assertion 引用 evidence ID + selector/offset；
- redaction 先于 persistence；
- full source bytes 不可用时 explicit unavailable，不用空字符串代替；
- source fingerprint 若需要，只允许本地 keyed HMAC；
- SSE logical event 与 transport read chunks 分开建模。

### A.5 Normalized IR

IR 顶层 Interaction，Item 是 tagged union：

~~~text
Message
ContentPart
ToolCall
ToolResult
ReasoningArtifact
Usage
Error
LifecycleEvent
ProviderExtension
~~~

每个 Item 必须含：

- ir_type、source_protocol、source_type；
- stable interaction/item/call relation；
- typed provider-native value；
- evidence_refs；
- extension namespace/payload ref；
- normalization transform ID/version；
- loss/unavailable markers。

IR 不做 normative 判定，不覆盖 raw evidence。OpenAI JSON string arguments 与 Google object args 必须保留 source type；无法 round-trip 的 transform 必须显式 loss marker，使相关 differential assertion inconclusive，而不是静默相等。

### A.6 Attempt、Assertion、Finding 与 Result

Attempt：

| 字段 | 内容 |
|---|---|
| attempt_id | invocation 下唯一 |
| execution_status | planned/running/completed/skipped/cancelled/errored |
| reason_code | 第 4.3 节；可空 |
| request/evidence refs | 脱敏 |
| driver/client observation | exact driver identity + refs |
| timings/usage/budget | unknown 与 0 分开 |
| residual resources | lease refs |

AssertionResult：

- assertion_result_id、assertion/requirement ID；
- assertion_role：precondition/normative/consumer_profile/behavioral/advisory；
- oracle ID/version/digest；
- verdict：pass/fail/warn/inconclusive；未执行 scenario 只用 plan_disposition，不伪造 Verdict；
- reason_code；
- expected/observed typed summary；
- evidence refs；
- deterministic/statistical；
- sample count、estimate、interval、method（统计时）；
- evaluator digest。

Precondition 在 target assertion 前运行；失败时 attempt errored/harness_error，后续 target assertion 标 not_observed（不创建 Verdict）、不进入 endpoint denominator、不产生 target Finding。

Finding：

- finding_id、assertion_result_id；
- fault_domain：第 3.1 节细粒度枚举；
- fault_family：transport/wire/protocol/model/client/harness/unknown，由 versioned taxonomy 从 fault_domain 派生并校验；
- category、severity；
- confidence 与 calibration version；
- alternative_domains；
- minimal evidence/repro refs；
- source requirement/ambiguity；
- remediation/upstream routing hint；
- fingerprint version/value。

CaseResult：

- scenario ID、plan_disposition、optional attempt IDs；
- execution_status + verdict/reason；
- assertion results/findings；
- applicable denominator membership；
- retry/attempt aggregation policy。

ProfileResult：

- profile/support lock/denominator digests；
- profile_outcome：compatible/degraded/incompatible/inconclusive；
- 五维 dimension_outcome；
- case/verdict/execution counts；
- hard gate results；
- known gaps、waivers（只展示，不改 verdict）；
- confidence/sample metadata。

聚合必须由 versioned ProfileGateOracle 完成。Harness errored attempt 不生成 target fail；unsupported capability 也不作为 Verdict。

### A.7 Compatibility Observation 与 DerivedEvaluation

Observation required 字段以第 19.2 节为准，另强制：

- original result bundle digest；
- exact oracle/core/pack/profile/driver/runner digests；
- equivalence_profile version/digest，以及其声明的 region、OS/arch、runtime/toolchain、gateway/transport/instrumentation dimensions；
- identity_level 与按等级要求的 target metadata；
- verdict_counts 与 execution_counts；
- denominator digest；
- artifact/redaction/retention class；
- submitter attestation relationship。

Registry-derived trust/freshness/dispute/supersession 不进入 observation_id。DerivedEvaluation 必须含 parent_observation_id、new evaluator/oracle/core digests、new result digest、reason、created_at 和 attestation；它不能冒充原运行。

### A.8 Driver RPC 最低状态机

Lifecycle：

~~~text
NEW
→ HELLO
→ PREPARED
→ INVOKING
→ PREPARED
→ SHUTDOWN
~~~

只有一个 invocation 时可串行；声明 concurrency capability 后才允许多个 invocation。每个 RPC envelope 含 jsonrpc、id、method/params 或 result/error；notification 不含 id。

Required methods：

- driver.hello：协议 version range、driver/SDK/client/runtime identity、artifact/lock digest、capabilities、permission request；
- driver.prepare：resolved_plan_digest、sandbox/capability token、fixture refs；返回 accepted permissions；
- driver.invoke：invocation_id、operation、ephemeral_exact_input_handle；Core 经受控 pipe/socket/memfd 提供精确输入，不默认持久化；
- driver.cancel：invocation_id、reason、deadline；返回 ack；
- driver.reset：无 active invocation 时清除 session state；
- driver.shutdown：停止并 flush；
- driver.observation notification：invocation_id、attempt_id、sequence、kind、monotonic offset；小 payload 可内联，大 payload 用受控 companion stream；
- driver.completed notification：terminal status、last sequence、summary digest。

Stable error classes：

~~~text
unsupported_rpc_version
invalid_state
invalid_request
permission_denied
budget_exceeded
capability_mismatch
driver_internal
cancellation_timeout
malformed_observation
artifact_mismatch
~~~

不变量：

- hello 前除 hello 外均 invalid_state；
- prepare 只能接受 Core 批准权限的子集；
- observation sequence 单调，terminal 后不得再发语义 observation；
- cancel ack 不等于已终止；Core 等待 completed 或 deadline 后杀进程组；
- Driver error → execution errored/reason driver_error，不生成 target fail；
- stdout 只有 RPC；stderr 有界并脱敏；
- Core 只在完成 redaction/CAS commit 后生成绑定当前 invocation 的 payload_ref。

Driver 不直接提供最终 payload_ref：它只提供 observation frames，Core 在 redaction 和 CAS commit 后生成 ref。Control frame 最大 1 MiB、data frame 默认 256 KiB；flow-control credit、总 bytes 与 deadline 都来自 ResolvedRunPlan。EOF/crash 使未完成 payload 无效，临时文件立即清理，不能被 Oracle 引用。

### A.9 Artifact Kind 与 Identity

| Kind | 作用 | 必备 identity |
|---|---|---|
| ProtocolPack | 某 protocol revision 的 requirements/scenarios/oracles | name、packVersion、protocolRevision、digest |
| ConformanceSuite | Pack 内 scenario/requirement selection | pack digest、suite name/version、denominator digest |
| ExternalSuiteAdapter | 运行并映射第三方 suite，不改其真值 | upstream project/version/digest、adapter version/digest |
| DialectAdapter | 显式转换某方言，strict 结果仍保留 | source/target dialect、version/digest、transform list |
| ProviderConnectionProfile | URL/auth/model metadata；不改 normative truth | provider、profileVersion、auth mode、digest |
| ConsumerCompatibilityProfile | 某 SDK/Agent 的 required packs/gates | profileVersion、consumerConstraint、digest |
| Driver | 实际 raw/SDK/client 执行器 | driver/RPC/runtime/package exact version/digest |
| RuntimeMetadataAdapter | 采集 runtime config/version，不发送 client 请求 | runtime/version range、adapter digest |

Profile publish 与 Run lock 分开：

- Profile artifact 用自身 SemVer 和 consumerConstraint；
- support-manifest 在 release 时解析 previous/current exact versions；
- ResolvedRunPlan 保存 resolved consumer/package/executable/image digest；
- Protocol revision、Pack version、Profile version、Consumer version 永不拼成一个字符串；
- OCI tag 只用于发现，digest 才是运行 identity。

### A.10 Schema Evolution

- Reader 必须忽略 schema 明确允许的 optional unknown extension，保留 raw；
- Core namespace 未知字段默认拒绝，防止拼写错误；
- 新 optional 字段可 minor；新增 required、删字段、改义、改默认隐私/denominator 是 breaking；
- enum 前向兼容策略逐字段声明，不能全局假设；
- v1 reader 支持全部已发布稳定 v1 schema，并支持 `schemas/migration-floor.yaml` 明确列出的 pre-1.0 corpus；列表为空时不得声称存在 v0 兼容承诺；
- 从 v2 起 reader 支持当前与前一稳定 major，或为前一 major 提供离线 migration；
- migration 生成新 object ID，保留 source ID/digest 和 migration tool digest；
- 每个 schema 有 positive、negative、old-reader、new-reader、round-trip、canonical digest fixtures；
- signature projection 和 display projection 分离并分别测试。

---

## 附录 B：术语表

| 术语 | 精确定义 |
|---|---|
| Harness | Core、planner、driver host、recorder、oracle、report 的总体测试系统 |
| Runner | 执行一次 ResolvedRunPlan 的环境/进程集合；可本地或 project-operated |
| Driver | 通过 raw HTTP、真实 SDK 或 Agent client 发请求并报告 client observation 的执行器 |
| Protocol Adapter | 解析某 protocol wire、构建 source-linked typed event；不发网络 |
| Runtime Metadata Adapter | 读取 serving runtime 版本/配置 fingerprint；不是 Driver |
| Dialect Adapter | 显式转换 provider 方言；不能覆盖 strict fail |
| Pack | 版本化 protocol requirements、scenarios、oracle binding 的 artifact |
| Conformance Suite | 一个 Pack 内的选择与 denominator，不是 Consumer Profile |
| Consumer Profile | 某精确 SDK/Agent 版本范围所需 packs/scenarios/gates |
| Provider Connection Profile | endpoint URL/auth/model metadata 规则，不改变 protocol truth |
| Requirement | 可追溯来源、level、解释和 scope 的可测试要求 |
| Scenario | 有预算、副作用、步骤、assertions 和 publication policy 的测试单元 |
| Plane | Endpoint black-box、Controlled Backend、Client Fixture Replay、Real Agent E2E 四种因果观察方式 |
| Evidence | 某 capture layer 的脱敏、内容寻址事实记录 |
| IR | 便于关系/差分的 normalized typed view；不是事实的替代 |
| Assertion | Oracle 对 evidence 的一次可重算判断 |
| Finding | 从 failed/warn/inconclusive assertion 派生的诊断与归因 |
| Dimension | Transport、Protocol、Model Behavior、Client Compatibility、Operational Reliability 五个顶层面 |
| Observation | 某一次 exact target/test/environment/result 的签名不可变记录 |
| Observation Class | 用于聚合同一 target/config/test identity 的比较 key |
| Trust Label | 来源/所有权/运行主体证据，不代表质量 |
| Freshness | Observation 对当前 rolling deployment/profile 的时间适用性 |
| Reproducibility Level | R0–R5，表示 evidence/target 可重现强度 |
| OpenAI Responses | OpenAI provider API 与 typed item/event contract |
| Open Responses | 独立开放规范/项目；通过 ExternalSuiteAdapter 集成 |

---

## 附录 C：权威 Manifests 与生成关系

手写长文容易漂移；P01 后以下文件是机器事实源：

| Manifest | 权威内容 | 生成/校验的文档 |
|---|---|---|
| sources.lock.yaml | 外部 claim/source/revision/license | §9、§15、§33 source tables |
| support/support-manifest.yaml | Artifact-kind applicability、Tier、逻辑 matrix cells/version selectors、owners、SLA | §6.1、§6.5、§16、E06/P04、release notes、Web Matrix 支持政策 |
| support/support-lock.yaml | 某次 release 解析后的 exact consumer/package/image versions/digests/cells | ResolvedRunPlan、E06/P04 gate、CI/release matrix、release notes、Web Matrix |
| support/release-components.yaml | core/packs/registry 的 release maturity/required | §6.2、§24、§25、§29、§30 release scope |
| execution/product-stage-map.yaml | Product Stage → Phase → Work Unit | §24、§25、§29 crosswalk |
| execution/impact-map.yaml | path/contract → affected Work Unit | reopen decisions |
| execution/phases/*、execution/work-units/* | Phase/Work Unit Goal contract、依赖、deliverable、gate | §24、§25、§29 phase/work-unit summaries |
| execution/metrics/definitions.yaml | formula/N/dataset/evaluator | §28.6、§29.4.1、§30 metrics |
| execution/transitions/* | 签名 StateEvent hash chain（Genesis/StateTransition/EvidenceAttachment），唯一权威状态与 evidence pointer | state-verify / phase-state view |
| execution/phase-state.yaml | 从 transition chain 生成的 active phase/unit 只读视图 | Goal status display |
| execution/ga-criteria.yaml | D30 kind/evaluator/evidence/waivable | §29 release aggregate、§30 |
| schemas/index.yaml | schema ID/version/digest/compat | API reference、§22.5、Appendix A |
| schemas/migration-floor.yaml | 明确 pre-1.0 migration corpus 或空列表 | §22.5、§30.4、A.10 |
| cli/spec.yaml | command/operand/flag/default/exit precedence/protected workflow commands | §17、§23.5、§29 command docs/completions |
| artifacts/identity-grammar.yaml | artifact kind/version/ref/hash projection | §9、Appendix A |

CI 执行 generate-docs 后必须得到零 diff；长文数字不得单独手改。Plan 在 P00 仍是 bootstrap 权威，P01 manifests 获批准后，执行状态以 manifests 为准，设计意图仍以 Plan/RFC/ADR 为准。

### C.1 产品阶段 Crosswalk

| Product Stage（§24） | Required Coding Work |
|---|---|
| Stage 0 需求验证 | P00 全部 Work Units |
| Stage 1 Conformance Kernel | P01、P02、P03 |
| Stage 2 Client-observed Lab | P04、P05；依赖 P03 已完成 Anthropic Tier 1 |
| Stage 3 Trusted Registry | P06 完整收敛后 P07 |
| Stage 4 RC/GA | P08、D30 |

### C.2 Evidence 权限边界

| Evidence Kind | 产生者 | 批准者/验证者 |
|---|---|---|
| MACHINE | 固定 evaluator/gate | independent evidence verifier |
| EXTERNAL | 上游 CI、adopter、审计方、Registry observation | schema/signature verifier + human sampling |
| TIME | 受保护 CI/Registry clock attestation | release workflow |
| HUMAN | 指定角色/无冲突 reviewer | signature/role policy |

Coding Agent 可以生成 MACHINE candidate 和 approval request，不能生成 EXTERNAL/TIME/HUMAN 事实。
