# 协议边界

**英文来源：** [Protocol Families](../protocols/README.md)（草案工作树，首次评审
commit 尚未产生）。

项目分别建模 OpenAI Chat、OpenAI Responses、Anthropic Messages、Google API 和
MCP，不把一个 provider 的字段/状态机强行套到另一个协议：

- Responses 保留 typed item/event 与 state/function lifecycle；
- Chat 保留 chunk/tool delta/finish reason 的独立语义；
- Anthropic 保留 version header、content block 和 tool lifecycle；
- Google `generateContent` 与 Interactions 分开；
- MCP 使用选定 stable revision 的 JSON-RPC lifecycle/capability。

所有 normative assertion 都必须绑定重新核验的一手来源、Requirement Catalog、
reference-pass 和 targeted-mutant-fail。当前没有任何 stable protocol pack 或支持等级。
