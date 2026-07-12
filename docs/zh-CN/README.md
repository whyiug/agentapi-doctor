# AgentAPI Doctor 简体中文核心指南

> 翻译状态：草案。本翻译不声明或虚构 source commit、独立评审、发布或批准。
> 发生歧义时，以英文版本、Plan 和受版本控制的 schema/manifest 为准。

- [从源码开始](getting-started.md)
- [架构与证据模型](architecture.md)
- [贡献指南](contributing.md)
- [协议边界](protocols.md)

项目仍处于 pre-Genesis、pre-release 阶段。当前可以从源码构建本地 candidate
CLI、合成 reference server 和 SQLite self-host Registry candidate，但没有稳定
release、Tier、兼容性认证、hosted Registry/verifier、正式 Adopters 列表、TSC
或 GA 结论。

Requirement Catalog 中的 260 个 candidate scenarios 是 metadata；当前本地
runner 按 target protocol 只执行 4 个候选检查，reference server 提供 12 个
可执行定向 mutation modes。不得把这些数字解释成 260 个已审核的可执行
mutant 或兼容性声明。
