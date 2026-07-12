# 快速开始

[项目中文首页](../../README.zh-CN.md) | [English](../quick-start.md)

两条命令即可运行不需要凭据的 demo。再用一条 `doctor test` 命令，就可以
评估任何获授权且提供受支持 API 形态的本地、私有网络或远程 HTTP(S)
endpoint。

## 安装当前源码快照

需要 Go 工具链：

```sh
go install github.com/whyiug/agentapi-doctor/cmd/doctor@latest
```

当前没有 tagged release 或已发布二进制软件包。`@latest` 是源码安装，
会跟随最新可用源码快照；以后重复执行可能安装不同代码。

如果找不到 `doctor`，请确认配置的 `GOBIN` 已加入 `PATH`；当 `GOBIN`
为空时，应加入 `$(go env GOPATH)/bin`。

## 运行内置 demo

```sh
doctor demo
```

Demo 使用进程内合成 fixture，不需要 API key；它会在随机 loopback 端口
启动临时 HTTP listener，在返回前将其停止，并且不访问外部 endpoint。
经过脱敏的本地证据会保存在 `.agentapi/` 下。

Demo 成功只验证已安装 CLI 及其合成 fixture，不能说明其他 endpoint 兼容。

## 测试获准评估的 endpoint

一次性接口为：

```text
doctor test --base-url URL --protocol ID --model ID
  [--auth-env NAME] [--auth-header x-api-key] [--allow-plain-http]
  --format terminal
```

不需要 `init` 步骤或 YAML 文件。

### 使用 Bearer 认证的 HTTPS

```sh
export DOCTOR_TOKEN='replace-with-a-test-token'

doctor test \
  --base-url 'https://replace-with-authorized-host.invalid/v1' \
  --protocol openai-chat \
  --model 'replace-with-model-id' \
  --auth-env DOCTOR_TOKEN \
  --format terminal
```

运行前请替换 `.invalid` URL 和 model。`--auth-env` 指定环境变量名称，
Token value 不会出现在命令行中。

- 无认证：省略 `--auth-env`。
- 自定义 Token Header：使用
  `--auth-env DOCTOR_TOKEN --auth-header x-api-key`。
- 可信本地/私有网络明文 HTTP：增加 `--allow-plain-http`。

默认拒绝明文 HTTP。通过不可信网络发送凭据时，不得使用
`--allow-plain-http`。该选项不会绕过对 metadata service、link-local、
multicast、unspecified 或无效目标地址的硬拒绝。

## 支持的 endpoint 形态

| 协议 ID | 派生 operation |
| --- | --- |
| `openai-chat` | `/v1/chat/completions` |
| `openai-responses` | `/v1/responses` |
| `anthropic-messages` | `/v1/messages` |

Endpoint 可以位于本机、私有网络或远程。非根路径会被视为完整 API prefix，
因此 `/v1` 和 `/api/v3` 等自定义 prefix 都会原样保留。请求始终限制在配置的
Origin，并且不跟随 redirect。

目标 endpoint 会收到有界的合成 prompt，并可能按其自身政策记录或保留这些
请求。请使用获授权的测试账号与测试凭据，不要通过这些检查发送生产数据。

## 成本、证据与结果边界

每次 endpoint run：

- 最多发送 **4 个请求**；
- 每个请求最多要求 **64 个 output tokens**；
- 使用一个 **60 秒执行 deadline**，随后执行有界 cleanup 和本地持久化；
- 输出指定的报告格式；
- 在 `.agentapi/` 下保存已脱敏证据和 run record。

当前 reference fixture 包含 12 个可执行定向模式。Catalog 中的 260 条候选
记录是 metadata，不是 260 个可执行请求。

只测试你获得明确授权的系统。PASS 只绑定到精确 endpoint、model、内置
pack/profile digest 和这 4 个检查；它不是厂商认证，也不能证明完整 SDK、
Agent、Provider 或部署兼容。

后续：[CLI 参考（英文）](../cli-reference.md) ·
[安装详情（英文）](../installation.md) ·
[故障排查（英文）](../troubleshooting.md) ·
[已知限制（英文）](../known-limitations/README.md)
