# AgentAPI Doctor 简体中文指南

[项目中文首页](../../README.zh-CN.md) | [English documentation](../README.md)

AgentAPI Doctor 正在积极开发。当前 `doctor` CLI 已提供带 checksum 的
`v0.1.0-rc.2` GitHub Release archive，但没有托管服务或已发布的包管理器渠道。
报告是绑定到被测版本和配置的可复现观察，不是厂商认证。

## 从这里开始

- [一条命令快速开始](quick-start.md)
- [从源码开始](getting-started.md)
- [安装（英文）](../installation.md)
- [配置（英文）](../configuration.md)
- [CLI 参考（英文）](../cli-reference.md)
- [故障排查（英文）](../troubleshooting.md)
- [已知限制（英文）](../known-limitations/README.md)
- [真实 OpenAI Python SDK 可复跑案例（英文）](../cases/openai-python-responses-null-output.md)

## 理解项目

- [架构与证据模型](architecture.md)
- [协议边界](protocols.md)
- [概念文档（英文）](../concepts/README.md)
- [协议族文档（英文）](../protocols/README.md)
- [客户端文档（英文）](../clients/README.md)
- [完整 Reference（英文）](../reference/README.md)

Requirement Catalog 中有 260 条候选 metadata 场景记录。当前本地
reference server 有 13 个可执行定向模式，一次普通 target run 会根据
target 协议选择 4 个检查。

## 安全、运维与贡献

- [安全与隐私（英文）](../security-and-privacy/README.md)
- [Registry（英文）](../registry/README.md)
- [运维（英文）](../operations/README.md)
- [贡献指南](contributing.md)
- [仓库贡献说明](../../CONTRIBUTING.md)
- [私密安全报告](../../SECURITY.md)

中文文档仍在完善。尚未翻译的详细页面会明确标注“英文”。机器可读行为
以仓库中的 versioned schema 和 `cli/spec.yaml` 为准；如果文档与它们
不一致，请把它当作文档 bug 报告。
