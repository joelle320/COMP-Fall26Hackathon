# Advisory Cursor integration example

The MVP provides a stdio MCP adapter and an advisory project rule. No Cursor installation, specific Cursor hook or client-version behavior has been verified in this environment. Verify the current client's documented MCP and project-rule mechanisms before enabling this example.

1. Start the local SENTINEL HTTP service and issue a short-lived narrowly scoped agent session through the authority API.
2. Configure the client's stdio MCP integration to launch `python -m sentinel.mcp_server` from the installed source environment. Supply `SENTINEL_URL` and the issued `SENTINEL_AGENT_TOKEN` using the client's secure environment configuration. The process must not receive the organizational authority token.
3. Inspect the exposed tools: `sentinel_execute` and `sentinel_delegate`. Run a benign synthetic sandbox read, then the provided controlled attack demonstrations.
4. If supported by the client, adapt [sentinel.mdc.example](sentinel.mdc.example) into its documented project-rule location. The format is illustrative and advisory; it is not an installed or verified interception hook.

MCP routes calls made to those tools to the gateway. It cannot intercept the client's built-in terminal, file editor, other MCP servers, browser requests or extensions. A protected agent that retains direct host tools can bypass this service by using them. Complete host enforcement requires runtime/OS isolation and removal of alternative execution paths.

Keep session credentials out of repositories, chat transcripts, command-line arguments and screenshots. Use only synthetic credentials in demonstrations. Verify the gateway's denied-action side-effect checks instead of assuming the client obeyed an instruction.
