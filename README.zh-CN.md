# AgentAPI Doctor

[English](README.md) | [简体中文](README.zh-CN.md)

**测试任何你获准评估的本地、私有网络或远程 HTTP(S) endpoint**，前提是
它提供 `openai-chat`、`openai-responses` 或
`anthropic-messages` 行为。AgentAPI Doctor 会保留经过脱敏的可复现证据，
而不是把一次成功请求当作兼容证明。

## 立即体验

```sh
go install github.com/whyiug/agentapi-doctor/cmd/doctor@latest
doctor demo
```

`doctor demo` 使用内置合成 fixture，不需要 API key，也不访问外部 endpoint。

> 当前没有 tagged release 或已发布二进制软件包。这是源码安装：`@latest`
> 会跟随最新可用的源码快照，不同时间安装的内容可能变化。

## 测试获准评估的 endpoint

```sh
export DOCTOR_TOKEN='replace-with-a-test-token'

doctor test \
  --base-url 'https://replace-with-authorized-host.invalid/v1' \
  --protocol openai-chat \
  --model 'replace-with-model-id' \
  --auth-env DOCTOR_TOKEN \
  --format terminal
```

运行前请替换 `.invalid` URL 和 model。无认证 endpoint 可省略
`--auth-env`。如果环境变量的值应放入自定义 Header 而不是 Bearer
`Authorization` Header，请增加 `--auth-header x-api-key`。除非显式增加
`--allow-plain-http`，否则会拒绝明文 HTTP；该选项只应用于可信本地或私有
网络 endpoint。

这个一次性命令不需要 `init` 或 YAML 配置。每次 endpoint run 最多发送
**4 个请求**，每个请求最多要求 **64 个 output tokens**，并使用
**60 秒执行 deadline**；它会输出所选报告格式，并在 `.agentapi/`
下保存已脱敏证据。

只测试你获得明确授权的系统。PASS 只绑定到精确 endpoint、model、内置
pack/profile digest 和这 4 个检查；它不是厂商认证，也不能证明完整 SDK、
Agent、Provider 或部署兼容。

## 文档

[快速开始](docs/zh-CN/quick-start.md) ·
[安装（英文）](docs/installation.md) ·
[CLI 参考（英文）](docs/cli-reference.md) ·
[故障排查（英文）](docs/troubleshooting.md) ·
[完整中文文档](docs/zh-CN/README.md)

提交改动前请阅读 [CONTRIBUTING.md](CONTRIBUTING.md)。按
[SECURITY.md](SECURITY.md) 私密报告疑似漏洞。

除非文件另有声明，源码和文档采用 [Apache License 2.0](LICENSE)。其他条款
见 [DATA_LICENSE.md](DATA_LICENSE.md) 和
[THIRD_PARTY_LICENSES.txt](THIRD_PARTY_LICENSES.txt)。
