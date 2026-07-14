# 快速开始

[项目中文首页](../../README.zh-CN.md) | [English](../quick-start.md)

安装一个 binary，先运行无需凭据的 demo，再检查任何获授权的本地、私有网络或
远程 endpoint。不需要初始化项目，也不需要 YAML。

`v0.1.1` 是正式的 Doctor distribution。项目仍处于 pre-1.0 阶段，因此 Go
package、实验 schema、Registry、driver 与 pack interface 都不是稳定公共 API，
除非 release 文档明确另有说明。

## 1. 安装 v0.1.1

Linux 或 macOS：

```sh
curl --proto '=https' --tlsv1.2 -fsSL \
  https://raw.githubusercontent.com/whyiug/agentapi-doctor/v0.1.1/install.sh | sh
export PATH="$HOME/.local/bin:$PATH"
```

脚本来自精确 release tag；它会先用该 release 的 `checksums.txt` 校验 archive，
再执行解压。如果希望先审阅：

```sh
curl --proto '=https' --tlsv1.2 -fSLO \
  https://raw.githubusercontent.com/whyiug/agentapi-doctor/v0.1.1/install.sh
less install.sh
sh install.sh
```

Windows 用户可以从
[v0.1.1](https://github.com/whyiug/agentapi-doctor/releases/tag/v0.1.1)
下载 `agentapi-doctor_0.1.1_windows_amd64.zip` 或
`agentapi-doctor_0.1.1_windows_arm64.zip`。精确 PowerShell checksum 与解压
步骤见[安装文档（英文）](../installation.md)。

## 2. 运行无 Key Demo

```sh
doctor demo
```

Demo 会在随机 loopback 端口启动进程内 fixture，执行 4 个检查，把脱敏证据保存
到 `.agentapi/`，并在返回前停止 fixture。它不访问外部 endpoint，也不需要
credential。

预期摘要：

```text
Result: CHECKS PASSED
Cases: 4 candidate / 4 applicable / 4 executed
Verdicts: PASS 4 | FAIL 0 | WARN 0 | INCONCLUSIVE 0 | SKIPPED 0 | ERRORED 0
Important conditions:
  [candidate_interpretations_pending_review] 候选 raw-wire 解释，不是认证结论。
```

这只验证安装的 CLI 和精确合成 fixture，不说明其他 endpoint 兼容。

> [!WARNING]
> Doctor 会在当前目录的 `.agentapi/` 下写入 run evidence。请把它视为私密本地
> 状态，并在下游项目中运行 Doctor 前，把以下内容加入该项目的 `.gitignore`：

```gitignore
.agentapi/
```

## 3. 检查获授权的 Endpoint

使用 Bearer 认证的 HTTPS endpoint：

```sh
export DOCTOR_TOKEN='replace-with-a-test-token'

doctor test \
  --base-url 'https://replace-with-authorized-host.invalid/v1' \
  --protocol openai-chat \
  --model 'replace-with-model-id' \
  --auth-env DOCTOR_TOKEN
```

运行前请替换 `.invalid` URL 和 model。`--auth-env` 指定环境变量名，Token value
不会进入命令行。

- 无认证：省略 `--auth-env`；
- 自定义 token header：增加 `--auth-header x-api-key`；
- 可信本地/私有网络明文 HTTP：增加 `--allow-plain-http`。

不要通过不可信明文网络发送 credential。Metadata、link-local、multicast、
unspecified 和无效目标仍会被拒绝。

## 支持的 Endpoint 形态

| Protocol ID | 从 API prefix 派生的 operation |
| --- | --- |
| `openai-chat` | `chat/completions` |
| `openai-responses` | `responses` |
| `anthropic-messages` | `messages` |

`/v1` 或 `/api/v3` 等 base path 会作为完整 API prefix 保留。请求不会离开配置的
origin，也不跟随 redirect。

## 阅读和分享结果

`CHECKS FAILED`、WARN 与 INCONCLUSIVE 结果会直接显示人类可读检查名和
expected/observed。证据能够支持 finding 时，报告还会显示 fault domain 和
remediation；不能支持时则明确标为未归因，并给出下一步审阅动作。即使有检查
失败，terminal 也会保留候选 interpretation 边界：

```text
Result: CHECKS FAILED
Cases: 4 candidate / 4 applicable / 4 executed
Verdicts: PASS 3 | FAIL 1 | WARN 0 | INCONCLUSIVE 0 | SKIPPED 0 | ERRORED 0
Important conditions:
  [candidate_interpretations_pending_review] 候选 raw-wire 解释，不是认证结论。
```

每次 run 结束时 terminal 也会打印精确导出命令：

```sh
doctor report markdown '<run-id>' --output doctor-report.md
doctor report html '<run-id>' --output doctor-report.html
```

分享前请人工审阅。已知 secret 会被脱敏，但结构化 model content 与 tool
arguments 不一定匿名。

## 请求与成本边界

每次 endpoint run：

- 最多发送 **4 个请求**；
- 使用一个 **60 秒 deadline**；
- 结构检查请求 **64 个 output tokens**，OpenAI Chat/Responses 的
  terminal-status 检查请求 **512 个**；
- 在私密的 `.agentapi/` 下保存 evidence 和 run record。

一次 4 请求的 Chat 或 Responses run 最多请求 704 个 output tokens，Anthropic
Messages 为 256 个。Output-token 字段只是向 Provider 提出的请求，不是客户端
强制成本上限；Provider 可以拒绝或忽略它。Provider 报告命中 token limit 时仍为
INCONCLUSIVE，reasoning-token usage 只用于诊断。PASS 只绑定精确 endpoint、model、
版本化 artifact 和执行的 4 个检查；它不是完整 SDK/Agent 兼容或厂商认证。

后续：[CLI 参考（英文）](../cli-reference.md) ·
[真实 SDK 案例（英文）](../cases/openai-python-responses-null-output.md) ·
[安装（英文）](../installation.md) ·
[故障排查（英文）](../troubleshooting.md) ·
[已知限制（英文）](../known-limitations/README.md)
