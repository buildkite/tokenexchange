# Single-user MCP gateway

A small Go reverse proxy that authenticates a demo credential, mints a short-lived Buildkite token for one configured user, and forwards MCP traffic to `https://mcp.buildkite.com/direct/readonly`. Tokens are cached and stay in the gateway; clients don't need their own Buildkite API tokens. No MCP SDK is required.

**This is a local demonstration, not corporate authentication.** Anyone with the demo secret acts as the configured Buildkite user. It listens only on loopback.

## Run

Requires Go 1.25+ and an Enterprise organization with Token Exchange enabled.

From the repository root:

1. Follow [Token Exchange setup](https://buildkite.com/docs/apis/oauth-token-exchange#setup) to generate a key and register an application. Register the public JWKS with a matching key ID; keep the private PEM locally. Grant `read_user`, `read_pipelines`, and `read_builds`. The user must be an active organization member with a verified email (or use their UUID).
2. Generate a separate demo secret and start the gateway:

   ```bash
   export GATEWAY_TOKEN="$(openssl rand -hex 32)"
   go run ./examples/mcp_gateway \
     -client-id YOUR_CLIENT_ID -private-key private_key.pem \
     -kid YOUR_KEY_ID -org YOUR_ORG -user-email you@example.com
   ```

   Use `-user-uuid` instead of `-user-email` if preferred. `-scopes` changes the
   requested scopes; add `read_build_logs` if your tools need logs. The gateway
   requests a five-minute token lifetime, capped by the application's maximum.
3. Configure an MCP client supporting Streamable HTTP and custom headers:

   - URL: `http://127.0.0.1:8080/mcp`
   - Header: `Authorization: Bearer <the value of GATEWAY_TOKEN>`

   Use the generated secret, not the literal environment-variable name. For a
   quick initialization check, run this in another shell with the same secret:

   ```bash
   curl -i http://127.0.0.1:8080/mcp \
     -H "Authorization: Bearer $GATEWAY_TOKEN" \
     -H 'Content-Type: application/json' \
     -H 'Accept: application/json, text/event-stream' \
     --data '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"gateway-demo","version":"1.0"}}}'
   ```
