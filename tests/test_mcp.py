import json

import httpx

from sentinel.mcp_server import MCPServer


def test_mcp_protocol_and_scoped_forwarding():
    requests = []

    def endpoint(request):
        requests.append(request)
        assert request.headers["authorization"] == "Bearer scoped-session-token"
        return httpx.Response(200, json={"executed": False, "decision": "deny"})

    with httpx.Client(base_url="http://127.0.0.1:8000", headers={"Authorization": "Bearer scoped-session-token"},
                      transport=httpx.MockTransport(endpoint)) as client:
        server = MCPServer(client)
        init = server.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize"})
        assert init["result"]["protocolVersion"] == "2024-11-05"
        assert server.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None
        tools = server.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})["result"]["tools"]
        assert {tool["name"] for tool in tools} == {"sentinel_execute", "sentinel_delegate"}
        response = server.handle({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {
            "name": "sentinel_execute", "arguments": {"tool": "terminal", "operation": "run", "content": "arbitrary"}}})
        assert json.loads(response["result"]["content"][0]["text"])["executed"] is False
        assert requests[0].url.path == "/api/gateway/execute"


def test_mcp_fail_closed_on_unavailable_gateway_and_unknown_tool():
    def unavailable(request):
        raise httpx.ConnectError("unavailable", request=request)

    with httpx.Client(base_url="http://127.0.0.1:8000", transport=httpx.MockTransport(unavailable)) as client:
        server = MCPServer(client)
        unknown = server.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "raw_shell"}})
        assert unknown["error"]["code"] == -32602
        failure = server.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "sentinel_execute"}})
        assert failure["result"]["isError"] is True
        assert "no tool executed" in failure["result"]["content"][0]["text"]
