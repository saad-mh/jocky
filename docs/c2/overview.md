# C2 Framework — Overview

## Why a Built-In C2

Remote code execution and persistent access are core research scenarios. A built-in C2 means you can deploy a `.jk` script to a remote agent without any external tooling: write the script, have the server push it, and the agent JIT-compiles and runs it on the remote host. The compiler's polymorphic obfuscation applies to every script execution — no two runs produce the same binary pattern.

The C2 is intentionally simple. It is not a production red-team framework. It provides exactly what a research workflow needs: multi-agent management, remote `.jk` execution, optional TLS, and a domain-fronting transport for scenarios where direct C2 traffic would be blocked or logged.

## Architecture

```
Operator (researcher)
        │  interactive_loop() — management shell
        ▼
  C2Server (asyncio TCP)
        │  newline-delimited JSON frames
        │  HELLO / CMD / RESULT / PING / PONG / BYE
        ▼
  AgentSession (per-connection state)
        │  exec_script() / exec_code()
        ▼
  Network (TCP, optional TLS)
        │
        ▼
  C2Agent (auto-reconnecting asyncio client)
        │  receives CMD frames
        │  dispatches: exec_script → compile_jocky(run_jit=True)
        │              exec_code   → write temp .jk → compile_jocky
        │              shell       → asyncio.create_subprocess_shell
        ▼
  Compiler (compiler/compiler.py)
```

For covert deployments, the agent can route traffic through `FrontedTransport` instead of a direct TCP connection:

```
Agent ──HTTP POST──► CDN edge node ──► (Host header) ──► C2 Server
       SNI = cdn.example.com              Host: c2.real-server.com
```

This makes the traffic appear as HTTPS to `cdn.example.com` from the network perspective.

## Protocol

All messages are newline-delimited JSON frames over a TCP (or TLS-wrapped TCP) connection. Maximum frame size is 64 MB.

| Type | Direction | Fields |
|---|---|---|
| `HELLO` | Agent → Server | `type`, `info` (hostname, platform, arch, python, pid, username) |
| `CMD` | Server → Agent | `type`, `cmd_id` (UUID), `action` (`exec_script`/`exec_code`/`shell`), `payload` |
| `RESULT` | Agent → Server | `type`, `cmd_id`, `status` (`ok`/`error`), `output`, `error` |
| `PING` | Server → Agent | `type` |
| `PONG` | Agent → Server | `type` |
| `BYE` | Either → Either | `type` |

The `cmd_id` UUID ties each `CMD` to its `RESULT`, allowing concurrent commands to be in flight.

## Agent Execution Modes

When the server issues a `CMD`:

| Action | What the agent does |
|---|---|
| `exec_script` | Reads a `.jk` file from the local filesystem and calls `compile_jocky(path, run_jit=True)` |
| `exec_code` | Writes the `payload` string to a temp `.jk` file and calls `compile_jocky(tmp_path, run_jit=True)` |
| `shell` | Runs `payload` as a shell command via `asyncio.create_subprocess_shell` |

The agent captures stdout/stderr from the JIT execution or shell command and returns it in the `RESULT` frame.

## TLS

Both server and agent support TLS. The server looks for `c2/server.crt` and `c2/server.key`. The agent connects with `ssl=True` using the standard library's SSL context.

When TLS is off (default for local testing), the connection is plaintext TCP.

## Domain Fronting

`c2/fronting.py` implements a transport that routes HTTP traffic through a CDN:

1. The agent opens a TCP (or SOCKS5-proxied) connection to the CDN's edge IP.
2. The TLS SNI (or HTTP `Host` header for plain HTTP) is set to the CDN front domain.
3. The `Host` HTTP header is set to the actual C2 server's domain.
4. The CDN forwards the request to the C2 server based on the `Host` header.

This makes the connection appear as HTTPS traffic to a legitimate CDN domain from external network monitoring.

## Reconnection and Keep-alive

- The `C2Agent` reconnects automatically after disconnection with a 10-second delay.
- A ping loop fires every 30 seconds to maintain the connection through NAT timeouts and load balancer idle checks.
- The management shell (`interactive_loop`) runs concurrently with the async server using `loop.run_in_executor`.

## Source Files

| File | Role |
|---|---|
| `c2/server.py` | `C2Server` + `AgentSession` |
| `c2/agent.py` | `C2Agent` |
| `c2/fronting.py` | `FrontedTransport`, `FrontedBeacon`, `socks5_connect` |
| `c2/__init__.py` | Package exports |
