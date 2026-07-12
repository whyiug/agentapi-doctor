# 从源码开始

**英文来源：** [Getting Started from Source](../getting-started/README.md)。
本页与英文文档都描述 pre-Genesis、pre-release 的源码候选，不代表已发布、
已认证或已进入任何支持 Tier。

## 本地合成快速开始

需要 `go.mod` 指定的 Go 工具链。以下命令不需要 API key，只启动
`127.0.0.1:8090` 回环监听，并在 shell 退出时清理本次启动的进程和临时日志。
请在全新 checkout 中运行，因为 `doctor init` 会拒绝覆盖已有配置。

```sh
git clone --branch agent/full-project-r4 --single-branch https://github.com/whyiug/agentapi-doctor.git
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

默认 `local-reference` 使用 `openai-responses`，因此本次运行只执行该协议
切片的 4 个 candidate checks，并把规范报告保存在 `.agentapi/runs`。
候选 runner 也包含 `openai-chat` 和 `anthropic-messages`，每个协议各 4 个
检查；一个 target 按自身 protocol 选择 4 个，并非一次执行 12 个。

## 离线检查计划

`--plan-only` 不连接 target、不解析 secret，也不写入 run evidence：

```sh
./bin/doctor test local-reference --plan-only
./bin/doctor test local-reference --plan-only --output ./local-plan.json
```

完整候选命令接口为：

```text
doctor test <target> [--config <path>] [--data-root <path>] [--plan-only] [--resolve] [--output <path>]
```

`--resolve` 只能与 `--plan-only` 一起使用；当前内置切片没有 capability
probe，IntentPlan 和精确 ResolvedRunPlan 均离线生成。普通运行把结果写入
`<data-root>/runs`；使用自定义 data root 后，报告命令应显式指定 store：

```sh
./bin/doctor test local-reference --data-root ./local-data
./bin/doctor report terminal latest --store ./local-data/runs
```

CI 和长期证据引用应使用精确 run ID，不要使用 `latest`。

## 正确解释结果

- 合成 reference fixture 上的 PASS 只证明该候选断言与该 fixture 的行为。
- 当前有 12 个可执行的定向 reference/mutant pairs；Requirement Catalog 中
  的 260 个 candidate scenarios 及 reference/mutant 记录是 metadata，不是
  260 个可执行 mutant。
- Catalog 仍为 `candidate` / `pending_review`，没有 Tier、真实 SDK/client
  验证、厂商背书或稳定兼容结论。
- 不得把真实 key、私有 trace、生产日志或未经授权的公网目标放进测试。

开发者可依次运行适用检查：

```sh
make -f Product.mk product-check
make test-protected-verifier
make -f Product.mk race-product
```

`make test-protected-verifier` 只运行边界明确的 verifier 单元测试，不产生
阶段状态。完整的 `make verify` 与 `make test-bootstrap` 都包含针对精确获批
P00.B00 candidate 的 whole-tree 保护断言；在 Genesis 之前，它们会按设计
拒绝当前独立的 product-candidate tree。即使在适用的独立 candidate 上得到
`candidate_valid`，也不代表激活 P00、批准 contract 或通过阶段门禁。
