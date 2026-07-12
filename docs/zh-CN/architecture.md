# 架构与证据模型

**英文来源：** [Compatibility Layers](../concepts/compatibility-layers.md)、
[Evidence and Oracles](../concepts/evidence-and-oracles.md)（草案工作树，首次评审
commit 尚未产生）。

AgentAPI Doctor 分开四个测试平面：endpoint black-box、controlled backend、
真实 client fixture replay 和最终 agent E2E。它也分开四个故障域：

- wire/transport：HTTP、SSE、JSON、TLS、redirect、cancel；
- provider/model：模型输出、tool 选择、结构化输出、usage；
- client/SDK：解析、校验、buffer、retry、事件与状态机；
- harness/task：fixture、oracle、环境、timeout 和任务逻辑。

证据不足时必须输出 unknown/inconclusive，不能从一个 SDK exception 猜成 provider
错误。Raw capture 保留原始顺序和 offset；normalized IR 保留 native type、转换版本、
raw evidence 引用和 loss marker。Normalizer 不得静默“修好”非法输入。

Pack 定义带来源的协议要求；Profile 定义某个 client 的期望和 denominator；Driver
运行固定版本的真实 client。三者的 digest、版本和职责不能混在一个“兼容模式”里。
