# 从源码开始

[中文文档首页](README.md) | [English](../getting-started/README.md)

本指南从源码 checkout 开始，依次完成授权 target 的配置、运行、证据保存和
报告导出。当前还没有 tagged release 或已发布软件包，PASS 也不是厂商认证。

如果只想走最短且不需要凭据的路径，请使用一条命令的
[快速开始](quick-start.md)。

## 前置条件

- Git
- `go.mod` 选定的 Go 工具链
- 用于下列示例的 POSIX 兼容 Shell
- 完整贡献者检查需要 Python 3 和 Make
- 只有容器检查和本地 Compose 服务需要 Docker

## 从默认分支构建

```sh
git clone https://github.com/whyiug/agentapi-doctor.git
cd agentapi-doctor

mkdir -p ./bin
go build -trimpath -o ./bin/doctor ./cmd/doctor
go build -trimpath -o ./bin/reference-server ./cmd/reference-server

./bin/doctor version
./bin/doctor self-check
```

Windows 用户可以用相同 package path 构建 `./bin/doctor.exe` 和
`./bin/reference-server.exe`。PowerShell 示例和本地 Docker 镜像说明见
[安装文档（英文）](../installation.md)。

## 初始化本地项目

```sh
./bin/doctor init
./bin/doctor target list
```

初始化会创建 `.agentapi/config.yaml`，但不会覆盖已有文件。生成的
`local-reference` target 指向 `http://127.0.0.1:8090/v1`，协议为
`openai-responses`。

修改文件或添加凭据前，请先阅读[配置文档（英文）](../configuration.md)。

## 运行合成 fixture

在一个 Shell 中启动仓库自带的 fixture：

```sh
./bin/reference-server -listen 127.0.0.1:8090
```

在另一个 Shell 中运行检查：

```sh
./bin/doctor test local-reference
./bin/doctor run inspect latest
./bin/doctor report terminal latest
```

只停止你自己启动的 reference-server 进程。普通运行会把规范记录保存在
`.agentapi/runs`，把已脱敏证据保存在 `.agentapi/evidence`。

## 添加获准测试的 endpoint

使用 secret reference，不要把 secret value 写入配置：

```sh
export EXAMPLE_API_TOKEN='replace-with-a-local-or-test-token'

./bin/doctor target add example \
  --base-url https://api.example.invalid/v1 \
  --protocol openai-responses \
  --model example-model \
  --auth-ref env://EXAMPLE_API_TOKEN
```

`example.invalid` 刻意设置为不可路由。只把它替换成你明确获准测试的本地
服务或 endpoint。

当前 runner 实现 `openai-chat`、`openai-responses` 和
`anthropic-messages`。它会根据协议在 base URL 后追加 operation path，
始终绑定到精确配置的 Origin，并且不跟随 redirect。

检查 target 时不会暴露 secret reference 的具体标识：

```sh
./bin/doctor target inspect example
```

## 在联网前检查计划

`--plan-only` 不连接 target、不解析凭据，也不写 run evidence：

```sh
./bin/doctor test example --plan-only
./bin/doctor test example --plan-only --resolve
./bin/doctor test example --plan-only --resolve --output ./example-plan.json
```

`--resolve` 必须与 `--plan-only` 一起使用；它包含离线生成的内置
`ResolvedRunPlan`，不会探测 target capability。只有目标路径不存在时才会创建
输出文件。

## 执行并保存精确 run reference

```sh
./bin/doctor test example
```

JSON 结果包含 `data.run_id` 和主退出码。CI 和长期证据应使用精确 run ID：

```sh
RUN_ID='<doctor-test-返回的精确-run-id>'
./bin/doctor run inspect "$RUN_ID" --allow-latest=false
./bin/doctor report json "$RUN_ID" --allow-latest=false --output ./doctor-report.json
```

`latest` 适合本地交互，但它是一个会变化的指针。

如果使用自定义 data root，后续命令需要指定对应 store：

```sh
./bin/doctor test local-reference --data-root ./local-data
./bin/doctor report terminal latest --store ./local-data/runs
```

## 导出报告和比较运行

报告格式包括 `terminal`、`json`、`junit`、`sarif`、`markdown` 和
`html`：

```sh
./bin/doctor report junit latest --output ./doctor-junit.xml
./bin/doctor report sarif latest --output ./doctor.sarif
./bin/doctor report html latest --output ./doctor-report.html
```

创建并比较本地 baseline：

```sh
./bin/doctor baseline accept latest --name local-known-good
./bin/doctor baseline list
./bin/doctor baseline compare latest --baseline local-known-good
```

也可以比较默认 store 中的两个精确 run：

```sh
OLD_RUN_ID='<较早的精确-run-id>'
NEW_RUN_ID='<较新的精确-run-id>'
./bin/doctor compare "$OLD_RUN_ID" "$NEW_RUN_ID"
```

完整 flag、baseline 命名、输出行为和退出码见
[CLI 参考（英文）](../cli-reference.md)。

## 正确解释结果

- 本地 fixture 是合成且确定性的；它的 PASS 只验证当前 runner 与 fixture。
- 一次普通 target run 会根据配置协议选择 4 个内置 raw-wire 检查。
- Reference server 当前有 12 个可执行定向模式。
- Requirement Catalog 中的 260 条候选场景记录是 metadata，不是 260 个
  可执行测试。
- 当前检查不能证明完整 SDK、Agent、模型、Provider 或部署兼容。
- 报告不是认证或背书，也不保证被测 endpoint、model、内置 pack/profile
  digest、plan 与 evidence 之外的行为；它不会自动证明 CLI 的源码 commit。

只测试你获准评估的 endpoint。不要把真实凭据、私有 trace 或未经脱敏的
payload 放进 issue 和 artifact。

## 运行贡献者检查

先运行最窄的相关测试，再运行适用的聚合命令：

```sh
make check
make test
make race
make docker-check
```

- `make check` 运行完整本地质量门。
- `make test` 运行全部 Go 测试。
- `make race` 使用 race detector 运行全部 Go 测试。
- `make docker-check` 构建并 smoke test 本地加固镜像目标。

贡献证据前阅读[合成 fixture（英文）](../getting-started/synthetic-fixtures.md)，
创建 PR 前阅读 [CONTRIBUTING.md](../../CONTRIBUTING.md)。

## 后续文档

- [故障排查（英文）](../troubleshooting.md)
- [概念（英文）](../concepts/README.md)
- [安全与隐私（英文）](../security-and-privacy/README.md)
- [Registry（英文）](../registry/README.md)
- [已知限制（英文）](../known-limitations/README.md)
