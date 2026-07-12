# AgentAPI Doctor

[English](README.md) | [简体中文](README.zh-CN.md)

AgentAPI Doctor 是一个证据优先的 Agentic LLM API 兼容性实验室。它帮助你
判断失败来自 HTTP/协议层、Provider 或模型、客户端，还是测试 Harness，并
保留可复现这一判断所需的证据。

> **项目状态：** 正在积极开发。当前 CLI 可以从源码构建并在本地运行，但
> 还没有 tagged release、已发布软件包或托管服务。PASS 只是绑定到具体版本
> 和配置的一次观察，不是厂商认证或背书。

## 当前可用能力

- 面向 `openai-chat`、`openai-responses` 和 `anthropic-messages` 的本地
  raw-HTTP runner。
- 每个 target 根据自身协议选择 4 个内置检查。
- 仅监听回环地址的合成 reference server，提供 12 个可执行的定向
  reference/mutant modes。
- 离线计划、请求/Token/时间硬预算、精确 Origin 传输、持久化前脱敏和
  内容寻址证据。
- 本地运行检查、对比、baseline，以及 terminal、JSON、JUnit、SARIF、
  Markdown 和独立 HTML 报告。
- 可从源码构建的 SQLite Registry、本地 Compose 配置和 Matrix UI。

Requirement Catalog 中有 **260 条候选场景记录**。这些记录是供后续覆盖和
评审使用的 metadata，并不是 260 个可执行测试。当前 reference server
提供 **12 个可执行定向模式**，而一次普通 target run 会根据 target 协议
选择 **4 个检查**。

## 60 秒本地检查

下面的例子只使用绑定到 `127.0.0.1` 的合成服务，不需要 API key，也不会
访问公网 endpoint。

```sh
git clone https://github.com/whyiug/agentapi-doctor.git
cd agentapi-doctor

mkdir -p ./bin
go build -o ./bin/doctor ./cmd/doctor
go build -o ./bin/reference-server ./cmd/reference-server

reference_log="${TMPDIR:-/tmp}/agentapi-doctor-reference.$$"
./bin/reference-server -listen 127.0.0.1:8090 >"$reference_log" 2>&1 &
reference_pid=$!
trap 'kill "$reference_pid" 2>/dev/null || true; wait "$reference_pid" 2>/dev/null || true; rm -f "$reference_log"' EXIT INT TERM
sleep 1

./bin/doctor init
./bin/doctor test local-reference
./bin/doctor report terminal latest
```

最终报告应显示 `COMPATIBLE`，并且本地 fixture 的 4 个 case 全部通过。这
只能验证仓库中的 runner 与 fixture 能协同工作，不能据此推断其他 endpoint
兼容。

更多解释和清理说明见[快速开始](docs/zh-CN/quick-start.md)。

## 安装与使用

当前还没有受支持的二进制或软件包 release。请使用 `go.mod` 选定的 Go
工具链构建当前源码：

```sh
mkdir -p ./bin
go build -trimpath -o ./bin/doctor ./cmd/doctor
./bin/doctor version
```

`make build` 会 compile-check 项目的全部命令，但不会安装二进制。也可以用
仓库中的 Dockerfile 在本地构建镜像。

从这里继续：

- [安装（英文）](docs/installation.md)
- [配置（英文）](docs/configuration.md)
- [CLI 参考（英文）](docs/cli-reference.md)
- [故障排查（英文）](docs/troubleshooting.md)
- [完整文档导航](docs/zh-CN/README.md)

## 开发

主要的本地检查命令为：

```sh
make check
make test
make race
make docker-check
```

提交改动前请阅读 [CONTRIBUTING.md](CONTRIBUTING.md)。Commit 需要包含
Developer Certificate of Origin sign-off。

## 安全与结果边界

只测试你明确获准评估的 endpoint 和源码仓库。不要把生产 key、私有 trace
或未经脱敏的 Provider payload 放进 issue、PR、fixture、report 或 artifact。

当前结果只覆盖有意保持精简的 raw-wire 切片，不能证明完整 SDK、Agent、
模型、Provider 或部署兼容。精确边界见
[已知限制](docs/known-limitations/README.md)。

## 社区与安全报告

- 使用 [SUPPORT.md](SUPPORT.md) 获取使用支持。
- 按 [SECURITY.md](SECURITY.md) 私密报告疑似漏洞。
- 遵守 [行为准则](CODE_OF_CONDUCT.md)。
- 项目维护方式见 [GOVERNANCE.md](GOVERNANCE.md) 和
  [MAINTAINERS.md](MAINTAINERS.md)。

## 许可证

除非文件另有声明，源码和文档采用
[Apache License 2.0](LICENSE)。数据集和 Registry 的专用条款见
[DATA_LICENSE.md](DATA_LICENSE.md)，依赖许可证全文汇总见
[THIRD_PARTY_LICENSES.txt](THIRD_PARTY_LICENSES.txt)。
