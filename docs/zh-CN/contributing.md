# 贡献指南

**英文来源：** [CONTRIBUTING.md](../../CONTRIBUTING.md) 与
[Documentation and Contribution Guide](../contributing/README.md)。

每个 commit 必须按照 Developer Certificate of Origin 1.1 添加真实签署：

```sh
git commit -s
```

小而完整的贡献包括：合成 fixture、Requirement source revision、一个 assertion
及其 reference-pass/mutant-fail、driver version bump、profile、错误信息或文档修复。

贡献时必须说明问题、包含/排除范围、Requirement/RFC/ADR、接口影响、安全与隐私、
测试计划、migration 和 provenance。不要复制许可不明的 SDK test、Issue 正文或用户
日志；公开可见不等于可以再许可。

漏洞、secret 和私有 trace 走 [私密安全报告流程](../../SECURITY.md)，不得创建公开
Issue。Contract 与外部证据应邀请独立复核；release gate 按仓库当前配置的
environment 规则审批。本项目目前不声称已经建立独立双人复核。
