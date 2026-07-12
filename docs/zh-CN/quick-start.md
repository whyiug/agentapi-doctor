# 快速开始

[中文文档首页](README.md) | [English](../quick-start.md)

Go 工具链准备好后，可以在约 60 秒内完成一次本地检查。这个例子只使用
`127.0.0.1` 上的确定性合成 API，不需要凭据，也不会访问公网 endpoint。

## 前置条件

- Git
- 仓库 `go.mod` 选定的 Go 工具链
- POSIX 兼容 Shell（Linux、macOS、WSL 或 Git Bash）

## 构建并运行

请使用全新 checkout，因为 `doctor init` 不会覆盖已有的
`.agentapi/config.yaml`。

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

Shell trap 只会停止本次会话启动的 reference 进程，并删除对应临时日志。

## 预期结果

Terminal 报告应包含：

```text
Profile outcome: COMPATIBLE
Cases: 4 candidate / 4 applicable / 4 executed
Verdicts: PASS 4
```

Run ID 会在本次运行时生成。结果和证据分别保存在
`.agentapi/runs` 与 `.agentapi/evidence`；这两个路径都已被 Git 忽略。

这个结果只能证明当前 runner 可以评估仓库中的合成 fixture。它不代表其他
endpoint 兼容，也不是厂商认证。

## 下一步

- 按[从源码开始](getting-started.md)添加获准测试的 target、检查离线计划并
  导出报告。
- 添加凭据前阅读[配置文档（英文）](../configuration.md)。
- 所有命令和退出码见 [CLI 参考（英文）](../cli-reference.md)。
- 如果端口被占用或初始化失败，查看[故障排查（英文）](../troubleshooting.md)。

Catalog 中有 260 条候选 metadata 场景记录。当前 reference server 有 12 个
可执行定向模式，而本快速开始只运行 `openai-responses` target 选择的 4 个
检查。
