#!/usr/bin/env python3
"""遥测 UDP 代理 + 操作网页。

功能要点：
- 按客户端 IP:端口建立会话，空闲超时（默认 5 秒）后过期；
- 建会话时把该会话固定到当前目标接收器（A/B），会话期间不随切换改变；
- 默认模式：每个会话使用一条独立的、已 connect 的上游 UDP 套接字（独立本地端口），
  因此回包天然只能属于一个会话；
- 固定源端口模式：接收器网段只放行代理的一个 UDP 源端口。代理所有会话
  （无论上游是 A 还是 B）都从同一个固定本地端口发送；每条报文前加一个
  代理生成的会话标识，接收器回包时带回该标识，代理据此把回包交给原会话。
  该模式只转发不超过 MAX_FORWARD_SIZE（默认 1400）字节的终端报文，超限丢弃并记日志；
  固定端口绑定失败时网页报错，绝不再换用其它端口继续转发；
- 会话过期即销毁其会话标识；旧会话迟到的回包找不到标识即丢弃，
  即使终端用原端口重连、代理重启后也一样；
- 报文与回包原样透传（固定端口模式附加的标识/观测信息由代理剥除，终端只见原始字节）；
- 当前目标与固定端口模式开关保存在 SQLite，重启后保留；会话全在内存，重启即清空；
- 切换目标时先落库再生效，保存失败则保留原目标；
- Flask 网页可切换目标、开关固定源端口模式、并行发两路试传报文、查看会话与日志。
"""

import asyncio
import os
import secrets
import socket
import sqlite3
import struct
import threading
import time

from flask import Flask, flash, jsonify, redirect, render_template, request, url_for

# ---------------- 配置 ----------------
UDP_LISTEN_HOST = os.environ.get("UDP_LISTEN_HOST", "0.0.0.0")
UDP_LISTEN_PORT = int(os.environ.get("UDP_LISTEN_PORT", "9000"))
HTTP_HOST = os.environ.get("HTTP_HOST", "0.0.0.0")
HTTP_PORT = int(os.environ.get("HTTP_PORT", "8080"))
DB_PATH = os.environ.get(
    "DB_PATH", os.path.join(os.path.dirname(os.path.abspath(__file__)), "proxy.db")
)
SESSION_IDLE_TIMEOUT = float(os.environ.get("SESSION_IDLE_TIMEOUT", "5"))
UPSTREAM_PORT_MIN = int(os.environ.get("UPSTREAM_PORT_MIN", "20000"))
UPSTREAM_PORT_MAX = int(os.environ.get("UPSTREAM_PORT_MAX", "29999"))
# 上游端口关闭后的冷却时间：冷却期内不再分配该端口，
# 保证旧会话迟到的回包不会被复用同端口的新会话收到。应大于接收器最大回包延迟。
UPSTREAM_PORT_COOLDOWN = float(os.environ.get("UPSTREAM_PORT_COOLDOWN", "30"))
LOG_KEEP = int(os.environ.get("LOG_KEEP", "1000"))

RECEIVERS = {
    "A": (
        os.environ.get("RECEIVER_A_HOST", "127.0.0.1"),
        int(os.environ.get("RECEIVER_A_PORT", "9001")),
    ),
    "B": (
        os.environ.get("RECEIVER_B_HOST", "127.0.0.1"),
        int(os.environ.get("RECEIVER_B_PORT", "9002")),
    ),
}
DEFAULT_TARGET = os.environ.get("DEFAULT_TARGET", "A")

# ---- 固定源端口模式 ----
# 接收器所在网段只放行代理的一个 UDP 源端口时启用：代理无论上游是 A 还是 B，
# 都从同一个本地 UDP 端口发送。接收器只接收来自该约定端口的报文，并据此回包。
FIXED_SOURCE_PORT_ENABLED = os.environ.get("FIXED_SOURCE_PORT_ENABLED", "0") == "1"
FIXED_SOURCE_PORT = int(os.environ.get("FIXED_SOURCE_PORT", "9500"))
# 固定端口模式下允许转发的最大终端报文（字节）；超限丢弃并记日志。
MAX_FORWARD_SIZE = int(os.environ.get("MAX_FORWARD_SIZE", "1400"))
# 代理给每个会话生成的标识：4 字节 magic + 16 位十六进制随机数（8 字节）。
# 随机数保证代理重启后新会话的标识不会与旧会话碰撞。
SESSION_TAG_MAGIC = os.environ.get("SESSION_TAG_MAGIC", "TLM1").encode()
assert len(SESSION_TAG_MAGIC) == 4, "SESSION_TAG_MAGIC 必须是 4 字节"
TAG_TOKEN_LEN = 16
TAG_LEN = len(SESSION_TAG_MAGIC) + TAG_TOKEN_LEN
# 接收器回包元信息：tag + b"SRC" + 2 字节源端口 + 原始回包
SRC_HEADER = b"SRC"
SRC_HEADER_LEN = len(SRC_HEADER) + 2
_HEX = set(b"0123456789abcdefABCDEF")


def fmt_addr(addr):
    return f"{addr[0]}:{addr[1]}"


def preview(data: bytes) -> str:
    """报文内容展示：可打印文本原样显示，否则用 hex。"""
    try:
        text = data.decode("utf-8")
        if all(ch.isprintable() or ch in "\r\n\t" for ch in text):
            return text if len(text) <= 200 else text[:200] + "…"
    except UnicodeDecodeError:
        pass
    hexed = data.hex()
    return "hex:" + (hexed if len(hexed) <= 200 else hexed[:200] + "…")


def fmt_ts(ts: float) -> str:
    return time.strftime("%H:%M:%S", time.localtime(ts)) + f".{int((ts % 1) * 1000):03d}"


def make_tag() -> bytes:
    return SESSION_TAG_MAGIC + secrets.token_hex(8).encode()


def parse_tag(data: bytes):
    """返回 (tag, 其余字节)；不是合法标识时返回 (None, data)。"""
    magic_len = len(SESSION_TAG_MAGIC)
    if len(data) < TAG_LEN or not data.startswith(SESSION_TAG_MAGIC):
        return None, data
    token = data[magic_len:TAG_LEN]
    if not all(c in _HEX for c in token):
        return None, data
    return data[:TAG_LEN], data[TAG_LEN:]


# ---------------- SQLite：目标/模式持久化 + 报文日志 ----------------
class Store:
    """线程安全的 SQLite 存取。目标与固定端口模式开关落库，重启后保留。"""

    def __init__(self, path):
        directory = os.path.dirname(os.path.abspath(path))
        os.makedirs(directory, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
        )
        self._conn.execute(
            """CREATE TABLE IF NOT EXISTS message_log (
                   id INTEGER PRIMARY KEY AUTOINCREMENT,
                   ts REAL NOT NULL,
                   client TEXT NOT NULL DEFAULT '',
                   session_id INTEGER NOT NULL DEFAULT 0,
                   direction TEXT NOT NULL,
                   receiver TEXT NOT NULL DEFAULT '',
                   payload TEXT NOT NULL DEFAULT '',
                   note TEXT NOT NULL DEFAULT '')"""
        )
        self._conn.commit()
        row = self._conn.execute("SELECT value FROM settings WHERE key='target'").fetchone()
        if row and row[0] in RECEIVERS:
            self._target = row[0]
        else:
            self._target = DEFAULT_TARGET if DEFAULT_TARGET in RECEIVERS else sorted(RECEIVERS)[0]
            self._conn.execute(
                "INSERT OR REPLACE INTO settings(key,value) VALUES('target',?)", (self._target,)
            )
            self._conn.commit()
        row = self._conn.execute("SELECT value FROM settings WHERE key='fixed_mode'").fetchone()
        if row and row[0] in ("0", "1"):
            self._fixed_mode = row[0] == "1"
        else:
            self._fixed_mode = FIXED_SOURCE_PORT_ENABLED
            self._conn.execute(
                "INSERT OR REPLACE INTO settings(key,value) VALUES('fixed_mode',?)",
                ("1" if self._fixed_mode else "0",),
            )
            self._conn.commit()
        self._inserts = 0

    def get_target(self):
        with self._lock:
            return self._target

    def set_target(self, target):
        """先持久化，成功后才切换内存中的当前目标；失败则抛异常并保留原目标。"""
        if target not in RECEIVERS:
            raise ValueError(f"未知接收器: {target!r}")
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO settings(key,value) VALUES('target',?)", (target,)
            )
            self._conn.commit()
            self._target = target

    def get_fixed_mode(self):
        with self._lock:
            return self._fixed_mode

    def set_setting(self, key, value):
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO settings(key,value) VALUES(?,?)", (key, value)
            )
            self._conn.commit()

    def log(self, direction, client="", session_id=0, receiver="", payload="", note=""):
        try:
            with self._lock:
                self._conn.execute(
                    "INSERT INTO message_log(ts,client,session_id,direction,receiver,payload,note)"
                    " VALUES(?,?,?,?,?,?,?)",
                    (time.time(), client, session_id, direction, receiver, payload, note),
                )
                self._conn.commit()
                self._inserts += 1
                if self._inserts % 200 == 0:
                    self._conn.execute(
                        "DELETE FROM message_log WHERE id < "
                        "(SELECT COALESCE(MIN(id),0) FROM "
                        "(SELECT id FROM message_log ORDER BY id DESC LIMIT ?))",
                        (LOG_KEEP,),
                    )
                    self._conn.commit()
        except sqlite3.Error:
            pass  # 日志失败绝不影响转发

    def recent_messages(self, limit=100):
        with self._lock:
            rows = self._conn.execute(
                "SELECT id,ts,client,session_id,direction,receiver,payload,note "
                "FROM message_log ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        cols = ("id", "ts", "client", "session_id", "direction", "receiver", "payload", "note")
        return [dict(zip(cols, r)) for r in rows]

    def latest_receiver_for_client(self, client):
        with self._lock:
            row = self._conn.execute(
                "SELECT receiver FROM message_log WHERE client=? AND direction='c2r' "
                "ORDER BY id DESC LIMIT 1",
                (client,),
            ).fetchone()
        return row[0] if row else None


# ---------------- 上游端口分配（带冷却期） ----------------
class PortAllocator:
    """显式管理上游本地端口：关闭后冷却期内不再分配，
    确保旧会话迟到的回包不会被复用同端口的新会话收到。"""

    def __init__(self, low, high, cooldown):
        self.low, self.high, self.cooldown = low, high, cooldown
        self._next = low
        self._in_use = set()
        self._closed = {}  # port -> 关闭时刻(monotonic)
        self._lock = threading.Lock()

    def allocate(self):
        with self._lock:
            now = time.monotonic()
            for _ in range(self.high - self.low + 1):
                port = self._next
                self._next += 1
                if self._next > self.high:
                    self._next = self.low
                if port in self._in_use:
                    continue
                closed_at = self._closed.get(port)
                if closed_at is not None and now - closed_at < self.cooldown:
                    continue
                self._in_use.add(port)
                self._closed.pop(port, None)
                return port
        raise RuntimeError("上游 UDP 端口耗尽")

    def release(self, port):
        with self._lock:
            self._in_use.discard(port)
            self._closed[port] = time.monotonic()

    def discard(self, port):
        """分配后绑定失败：不进入冷却，直接可用。"""
        with self._lock:
            self._in_use.discard(port)


# ---------------- 会话与转发 ----------------
class Session:
    __slots__ = (
        "id", "client_addr", "receiver_name", "receiver_addr",
        "upstream_port", "transport", "state", "closed",
        "created", "last_activity", "pending", "mode", "tag",
        "observed_source_port",
    )

    def __init__(self, sid, client_addr):
        self.id = sid
        self.client_addr = client_addr
        self.receiver_name = ""
        self.receiver_addr = None
        self.upstream_port = None
        self.transport = None
        self.state = "opening"  # opening -> open -> closed
        self.closed = False
        self.created = time.monotonic()
        self.last_activity = self.created
        self.pending = []
        self.mode = "per-session"  # per-session | fixed
        self.tag = None
        self.observed_source_port = None


class ClientProtocol(asyncio.DatagramProtocol):
    """面向遥测终端的 UDP 端。"""

    def __init__(self, state):
        self.state = state

    def datagram_received(self, data, addr):
        self.state.on_client_datagram(data, addr)

    def error_received(self, exc):
        pass


class UpstreamProtocol(asyncio.DatagramProtocol):
    """每个会话一条、已 connect 到其接收器的上游 UDP 端。
    只有该会话对应接收器的回包会到达这里。"""

    def __init__(self, state):
        self.state = state
        self.session = None

    def datagram_received(self, data, addr):
        sess = self.session
        if sess is not None:
            self.state.on_upstream_datagram(sess, data)

    def error_received(self, exc):
        pass  # 如对端 ICMP 不可达，忽略


class FixedPortProtocol(asyncio.DatagramProtocol):
    """固定源端口模式下的唯一上游套接字：所有会话共用，回包靠会话标识区分。"""

    def __init__(self, state):
        self.state = state

    def datagram_received(self, data, addr):
        self.state.on_fixed_datagram(data, addr)

    def error_received(self, exc):
        pass


class ProxyState:
    def __init__(self, store):
        self.store = store
        self.loop = None
        self.client_transport = None
        self.sessions = {}  # client_addr -> Session（仅事件循环线程修改）
        self.tags = {}  # tag(bytes) -> Session（仅固定端口模式）
        self.lock = threading.RLock()
        self.next_session_id = 1
        self.ports = PortAllocator(UPSTREAM_PORT_MIN, UPSTREAM_PORT_MAX, UPSTREAM_PORT_COOLDOWN)
        # 接收器地址预解析，固定端口模式下用于核对回包来源
        self.receiver_endpoints = {}
        self._resolved = {}
        self.fixed_requested = store.get_fixed_mode()
        self.fixed_active = False
        self.fixed_error = ""
        self.fixed_transport = None
        self.fixed_port = FIXED_SOURCE_PORT

    async def start(self):
        self._resolve_receivers()
        # 固定端口模式若已开启，先绑定固定端口，再开始接收终端报文，
        # 避免启动瞬间的报文走错转发路径。绑定失败则 fail-closed（不换端口）。
        if self.fixed_requested:
            ok, err = await self.enable_fixed()
            if not ok:
                print(f"[proxy] 固定源端口模式启动失败: {err}", flush=True)
        else:
            print("[proxy] 固定源端口模式关闭，按每会话独立上游端口转发", flush=True)
        transport, _ = await self.loop.create_datagram_endpoint(
            lambda: ClientProtocol(self),
            local_addr=(UDP_LISTEN_HOST, UDP_LISTEN_PORT),
        )
        self.client_transport = transport
        self.loop.create_task(self._sweeper())
        print(f"[proxy] 客户端 UDP 监听 {UDP_LISTEN_HOST}:{UDP_LISTEN_PORT}", flush=True)
        print(f"[proxy] 空闲会话超时 {SESSION_IDLE_TIMEOUT}s，当前目标 {self.store.get_target()}",
              flush=True)

    def _resolve_receivers(self):
        """把接收器主机名解析成数字地址；失败则退回原值并标记为未解析。"""
        for name in RECEIVERS:
            self._endpoint(name)
        print(f"[proxy] 接收器地址 {self.receiver_endpoints}", flush=True)

    def _endpoint(self, name):
        """返回 (host, port)；主机名解析成功后缓存数字地址，用于核对回包来源。"""
        if self._resolved.get(name):
            return self.receiver_endpoints[name]
        host, port = RECEIVERS[name]
        try:
            ip = socket.gethostbyname(host)
        except OSError:
            self.receiver_endpoints[name] = (host, port)
            return self.receiver_endpoints[name]
        self._resolved[name] = True
        self.receiver_endpoints[name] = (ip, port)
        return self.receiver_endpoints[name]

    # ---- 固定源端口模式开关（在事件循环线程中执行） ----
    async def enable_fixed(self):
        """绑定固定源端口并切到固定端口转发。绑定失败绝不换端口。"""
        with self.lock:
            if self.fixed_active:
                return True, ""
            self.fixed_requested = True
        try:
            transport, _ = await self.loop.create_datagram_endpoint(
                lambda: FixedPortProtocol(self),
                local_addr=("0.0.0.0", FIXED_SOURCE_PORT),
            )
        except OSError as exc:
            msg = f"固定源端口 {FIXED_SOURCE_PORT} 绑定失败（{exc}）；不会改用其它端口转发"
            with self.lock:
                self.fixed_requested = True
                self.fixed_active = False
                self.fixed_error = msg
                for sess in list(self.sessions.values()):
                    self._close_session(sess, "固定源端口模式启用失败")
                self.tags.clear()
            self._publish_fixed_mode(True)
            return False, msg
        transport.get_extra_info("socket").setsockopt(
            socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 20
        )
        with self.lock:
            for sess in list(self.sessions.values()):
                self._close_session(sess, "切换到固定源端口模式")
            self.tags.clear()
            self.fixed_transport = transport
            self.fixed_port = FIXED_SOURCE_PORT
            self.fixed_active = True
            self.fixed_requested = True
            self.fixed_error = ""
        self._publish_fixed_mode(True)
        return True, ""

    async def disable_fixed(self):
        with self.lock:
            transport, self.fixed_transport = self.fixed_transport, None
            for sess in list(self.sessions.values()):
                self._close_session(sess, "关闭固定源端口模式")
            self.tags.clear()
            self.fixed_active = False
            self.fixed_requested = False
            self.fixed_error = ""
        if transport is not None:
            transport.close()
        self._publish_fixed_mode(False)
        return True, ""

    def _persist_fixed_mode(self, enabled):
        try:
            self.store.set_setting("fixed_mode", "1" if enabled else "0")
        except sqlite3.Error as exc:
            print(f"[proxy] 固定端口模式开关保存失败: {exc}", flush=True)

    def _publish_fixed_mode(self, enabled):
        """开关成功后写库，并把“模式已实际生效”记入日志。"""
        self._persist_fixed_mode(enabled)
        if not enabled:
            self.store.log("event", note="已关闭固定源端口模式，恢复每会话独立上游端口转发")
            print("[proxy] 固定源端口模式关闭", flush=True)
            return
        if self.fixed_active:
            self.store.log("event",
                           note=f"已启用固定源端口模式，所有会话从 UDP {FIXED_SOURCE_PORT} 发出")
            print(f"[proxy] 固定源端口模式启用：UDP {FIXED_SOURCE_PORT}", flush=True)
        else:
            self.store.log("event",
                           note=f"固定源端口模式已请求启用，但端口 {FIXED_SOURCE_PORT} 不可用；"
                                f"不会改用其它端口转发")
            print(f"[proxy] 固定源端口模式不可用：{self.fixed_error}", flush=True)

    def apply_fixed_mode(self, enabled):
        """供 Flask 线程同步调用。"""
        if self.loop is None:
            return False, "代理事件循环尚未就绪"
        coro = self.enable_fixed() if enabled else self.disable_fixed()
        try:
            return asyncio.run_coroutine_threadsafe(coro, self.loop).result(10)
        except Exception as exc:
            return False, f"操作失败: {exc}"

    def fixed_status(self):
        with self.lock:
            return {
                "requested": self.fixed_requested,
                "active": self.fixed_active,
                "port": self.fixed_port,
                "error": self.fixed_error,
                "max_forward_size": MAX_FORWARD_SIZE,
            }

    # ---- 客户端方向 ----
    def on_client_datagram(self, data, addr):
        now = time.monotonic()
        fixed_requested, fixed_active = self.fixed_requested, self.fixed_active
        if fixed_requested:
            if not fixed_active:
                self.store.log(
                    "drop", client=fmt_addr(addr), payload=preview(data),
                    note=f"固定源端口模式不可用，报文未转发：{self.fixed_error or '未绑定'}",
                )
                return
            self._on_client_datagram_fixed(data, addr, now)
            return
        with self.lock:
            sess = self.sessions.get(addr)
            if sess is not None and sess.closed:
                sess = None
            if (sess is not None and sess.state == "open"
                    and now - sess.last_activity > SESSION_IDLE_TIMEOUT):
                self._close_session(sess, "idle-timeout")
                sess = None
            if sess is None:
                # 建会话：固定到“当前”目标接收器
                sess = Session(self.next_session_id, addr)
                self.next_session_id += 1
                self.sessions[addr] = sess
                sess.pending.append(data)
                self.loop.create_task(self._open_session(sess))
                return
            sess.last_activity = now
            if sess.state == "opening":
                sess.pending.append(data)
                return
        self._forward(sess, data)

    def _on_client_datagram_fixed(self, data, addr, now):
        """固定源端口模式：会话无需异步建套接字，直接分配标识并转发。"""
        created = False
        with self.lock:
            sess = self.sessions.get(addr)
            if sess is not None and (sess.closed or sess.mode != "fixed"):
                sess = None
            if sess is not None and now - sess.last_activity > SESSION_IDLE_TIMEOUT:
                self._close_session(sess, "idle-timeout")
                sess = None
            if sess is None:
                target = self.store.get_target()  # 建会话时固定接收器
                sess = Session(self.next_session_id, addr)
                self.next_session_id += 1
                sess.mode = "fixed"
                sess.receiver_name = target
                sess.receiver_addr = self._endpoint(target)
                sess.tag = make_tag()
                sess.state = "open"
                self.sessions[addr] = sess
                self.tags[sess.tag] = sess
                created = True
            sess.last_activity = now
        if created:
            self.store.log("event", client=fmt_addr(addr), session_id=sess.id,
                           receiver=sess.receiver_name,
                           note=f"会话建立（固定源端口模式），固定到接收器 "
                                f"{sess.receiver_name}，标识 {sess.tag[4:].decode()}")
        self._forward_fixed(sess, data)

    def _forward_fixed(self, sess, data):
        if len(data) > MAX_FORWARD_SIZE:
            self.store.log(
                "drop", client=fmt_addr(sess.client_addr), session_id=sess.id,
                receiver=sess.receiver_name, payload=preview(data),
                note=f"报文 {len(data)} 字节超过固定端口模式上限 "
                     f"{MAX_FORWARD_SIZE} 字节，已丢弃",
            )
            return
        transport = self.fixed_transport
        if sess.closed or transport is None:
            return
        try:
            transport.sendto(sess.tag + data, sess.receiver_addr)
        except Exception as exc:
            self.store.log("event", client=fmt_addr(sess.client_addr), session_id=sess.id,
                           note=f"转发失败: {exc}")
            return
        self._log_forwarded(sess, data, note=f"固定源端口 {self.fixed_port}")

    def _log_forwarded(self, sess, data, note=""):
        self.store.log("c2r", client=fmt_addr(sess.client_addr), session_id=sess.id,
                       receiver=sess.receiver_name, payload=preview(data), note=note)

    async def _open_session(self, sess):
        target = self.store.get_target()  # 建会话时固定接收器
        host, port = RECEIVERS[target]
        client = fmt_addr(sess.client_addr)
        try:
            transport = None
            upstream_port = None
            last_err = None
            for _ in range(8):
                upstream_port = self.ports.allocate()
                try:
                    transport, proto = await self.loop.create_datagram_endpoint(
                        lambda: UpstreamProtocol(self),
                        local_addr=("0.0.0.0", upstream_port),
                        remote_addr=(host, port),  # connect：只收该接收器的回包
                    )
                    break
                except OSError as exc:
                    last_err = exc
                    self.ports.discard(upstream_port)
            if transport is None:
                raise last_err or RuntimeError("无可用上游端口")
            with self.lock:
                if sess.closed:
                    transport.close()
                    self.ports.release(upstream_port)
                    return
                sess.receiver_name = target
                sess.receiver_addr = (host, port)
                sess.upstream_port = upstream_port
                sess.transport = transport
                sess.state = "open"
                proto.session = sess
                pending, sess.pending = sess.pending, []
            self.store.log("event", client=client, session_id=sess.id, receiver=target,
                           note=f"会话建立，固定到接收器 {target}（上游端口 {upstream_port}）")
            for data in pending:
                self._forward(sess, data)
        except Exception as exc:
            self.store.log("event", client=client, session_id=sess.id,
                           note=f"会话建立失败: {exc}")
            self.close_session(sess, f"open-failed: {exc}")

    def _forward(self, sess, data):
        with self.lock:
            if sess.closed or sess.transport is None:
                return
            sess.last_activity = time.monotonic()
        try:
            sess.transport.sendto(data)  # 已 connect，原样发往该会话的接收器
        except Exception as exc:
            self.store.log("event", client=fmt_addr(sess.client_addr), session_id=sess.id,
                           note=f"转发失败: {exc}")
            return
        self._log_forwarded(sess, data)

    # ---- 接收器方向 ----
    def on_upstream_datagram(self, sess, data):
        now = time.monotonic()
        with self.lock:
            if sess.closed or self.sessions.get(sess.client_addr) is not sess:
                self.store.log("drop", client=fmt_addr(sess.client_addr), session_id=sess.id,
                               receiver=sess.receiver_name, payload=preview(data),
                               note="旧会话迟到的回包，已丢弃")
                return
            if now - sess.last_activity > SESSION_IDLE_TIMEOUT:
                self._close_session(sess, "idle-timeout")
                self.store.log("drop", client=fmt_addr(sess.client_addr), session_id=sess.id,
                               receiver=sess.receiver_name, payload=preview(data),
                               note="回包到达时会话已过期，已丢弃")
                return
            sess.last_activity = now
        self.client_transport.sendto(data, sess.client_addr)  # 原样送回该客户端
        self.store.log("r2c", client=fmt_addr(sess.client_addr), session_id=sess.id,
                       receiver=sess.receiver_name, payload=preview(data))

    def _reply_source_ok(self, sess, addr):
        """固定端口模式下核对回包确实来自该会话的接收器。"""
        host, port = sess.receiver_addr
        if addr[1] != port:
            return False
        if self._resolved.get(sess.receiver_name, False):
            return addr[0] == host
        return True

    def on_fixed_datagram(self, data, addr):
        now = time.monotonic()
        tag, rest = parse_tag(data)
        if tag is None:
            self.store.log("drop", client=fmt_addr(addr), receiver="?",
                           payload=preview(data),
                           note="回包缺少会话标识，无法归属，已丢弃")
            return
        observed = None
        payload = rest
        if rest.startswith(SRC_HEADER) and len(rest) >= SRC_HEADER_LEN:
            observed = struct.unpack("!H", rest[len(SRC_HEADER):SRC_HEADER_LEN])[0]
            payload = rest[SRC_HEADER_LEN:]
        with self.lock:
            sess = self.tags.get(tag)
            if (sess is None or sess.closed
                    or self.sessions.get(sess.client_addr) is not sess):
                self.store.log(
                    "drop", client=fmt_addr(addr), receiver="?",
                    payload=preview(payload),
                    note=f"回包标识 {tag[4:].decode()} 无对应会话"
                         f"（已过期或代理曾重启），已丢弃",
                )
                return
            if not self._reply_source_ok(sess, addr):
                self.store.log(
                    "drop", client=fmt_addr(sess.client_addr), session_id=sess.id,
                    receiver=sess.receiver_name, payload=preview(payload),
                    note=f"回包来源 {fmt_addr(addr)} 与会话接收器不符，已丢弃",
                )
                return
            if now - sess.last_activity > SESSION_IDLE_TIMEOUT:
                self._close_session(sess, "idle-timeout")
                self.store.log("drop", client=fmt_addr(sess.client_addr), session_id=sess.id,
                               receiver=sess.receiver_name, payload=preview(payload),
                               note="回包到达时会话已过期，已丢弃")
                return
            sess.last_activity = now
            sess.observed_source_port = observed
        self.client_transport.sendto(payload, sess.client_addr)  # 剥除标识，终端只见原始字节
        self.store.log("r2c", client=fmt_addr(sess.client_addr), session_id=sess.id,
                       receiver=sess.receiver_name, payload=preview(payload),
                       note=f"接收器观测源端口 {observed}，固定源端口 {self.fixed_port}"
                            if observed is not None else "")

    # ---- 会话生命周期 ----
    def _close_session(self, sess, reason):
        """调用方需持有 self.lock。"""
        if sess.closed:
            return
        sess.closed = True
        sess.state = "closed"
        if self.sessions.get(sess.client_addr) is sess:
            del self.sessions[sess.client_addr]
        if sess.tag is not None and self.tags.get(sess.tag) is sess:
            del self.tags[sess.tag]
        if sess.mode == "fixed":
            sess.transport = None  # 共享套接字不随会话关闭
            sess.upstream_port = None
        else:
            transport, sess.transport = sess.transport, None
            port, sess.upstream_port = sess.upstream_port, None
            if transport is not None:
                transport.close()  # 迟到的回包到此端口将被系统丢弃
            if port is not None:
                self.ports.release(port)  # 进入冷却期，冷却内不再分配
        self.store.log("event", client=fmt_addr(sess.client_addr), session_id=sess.id,
                       receiver=sess.receiver_name, note=f"会话关闭（{reason}）")

    def close_session(self, sess, reason):
        with self.lock:
            self._close_session(sess, reason)

    async def _sweeper(self):
        while True:
            await asyncio.sleep(0.25)
            now = time.monotonic()
            with self.lock:
                expired = [s for s in self.sessions.values()
                           if not s.closed and now - s.last_activity > SESSION_IDLE_TIMEOUT]
                for sess in expired:
                    self._close_session(sess, "idle-timeout")

    def snapshot_sessions(self):
        now = time.monotonic()
        with self.lock:
            def source_port(s):
                if s.mode != "fixed":
                    return s.upstream_port
                # 接收器尚未回过包时显示配置的固定端口，回过包后显示实测端口
                return s.observed_source_port if s.observed_source_port is not None \
                    else self.fixed_port

            return [
                {
                    "id": s.id,
                    "client": fmt_addr(s.client_addr),
                    "receiver": s.receiver_name or "?",
                    "upstream_port": s.upstream_port,
                    "mode": "固定端口" if s.mode == "fixed" else "独立端口",
                    "source_port": source_port(s),
                    "state": s.state,
                    "idle": round(now - s.last_activity, 1),
                    "age": round(now - s.created, 1),
                }
                for s in sorted(self.sessions.values(), key=lambda x: x.id)
            ]

    def client_info(self, client):
        """按 "ip:port" 查活动会话信息（试传结果展示用）。"""
        with self.lock:
            for s in self.sessions.values():
                if fmt_addr(s.client_addr) == client:
                    return {
                        "receiver": s.receiver_name or None,
                        "session_id": s.id,
                        "mode": "fixed" if s.mode == "fixed" else "per-session",
                        "observed_source_port": s.observed_source_port,
                        "upstream_port": s.upstream_port,
                    }
        return None


# ---------------- Flask 网页 ----------------
store = Store(DB_PATH)
state = ProxyState(store)
app = Flask(__name__)
app.secret_key = os.urandom(16)

_last_tests = []
_last_test_lock = threading.Lock()

DIRECTION_LABELS = {
    "c2r": "客户端→接收器",
    "r2c": "接收器→客户端",
    "event": "事件",
    "drop": "丢弃",
}


def _format_message(m):
    m = dict(m)
    m["ts"] = fmt_ts(m["ts"])
    m["direction"] = DIRECTION_LABELS.get(m["direction"], m["direction"])
    return m


@app.get("/")
def index():
    with _last_test_lock:
        tests = [dict(t) for t in _last_tests]
    return render_template(
        "index.html",
        target=store.get_target(),
        receivers={k: f"{h}:{p}" for k, (h, p) in RECEIVERS.items()},
        idle_timeout=SESSION_IDLE_TIMEOUT,
        udp_listen_port=UDP_LISTEN_PORT,
        fixed=state.fixed_status(),
        last_tests=tests,
    )


@app.get("/api/state")
def api_state():
    with _last_test_lock:
        tests = [dict(t) for t in _last_tests]
    return jsonify({
        "target": store.get_target(),
        "receivers": {k: f"{h}:{p}" for k, (h, p) in RECEIVERS.items()},
        "idle_timeout": SESSION_IDLE_TIMEOUT,
        "fixed": state.fixed_status(),
        "sessions": state.snapshot_sessions(),
        "messages": [_format_message(m) for m in store.recent_messages(100)],
        "last_tests": tests,
        "last_test": tests[0] if tests else None,
    })


@app.post("/switch")
def switch():
    target = request.form.get("target", "")
    try:
        store.set_target(target)
        store.log("event", note=f"网页切换目标为接收器 {target}")
        flash(f"已切换到接收器 {target}。新会话走 {target}，旧会话继续走原接收器直至过期。", "ok")
    except Exception as exc:
        flash(f"切换保存失败，保留原目标 {store.get_target()}。原因：{exc}", "error")
    return redirect(url_for("index"))


@app.post("/mode")
def mode():
    action = request.form.get("action", "")
    if action == "enable":
        ok, err = state.apply_fixed_mode(True)
        if ok:
            flash(f"已启用固定源端口模式：所有会话从 UDP {FIXED_SOURCE_PORT} 发出，"
                  f"单条终端报文上限 {MAX_FORWARD_SIZE} 字节。", "ok")
        else:
            flash(f"启用固定源端口模式失败：{err}", "error")
    elif action == "disable":
        ok, err = state.apply_fixed_mode(False)
        if ok:
            flash("已关闭固定源端口模式，恢复每会话独立上游端口转发。", "ok")
        else:
            flash(f"关闭固定源端口模式失败：{err}", "error")
    else:
        flash("未知操作。", "error")
    return redirect(url_for("index"))


@app.post("/test")
def test():
    global _last_tests
    lanes = []
    for suffix in ("", "2"):
        payload = request.form.get("payload" + suffix, "").strip()
        if suffix and not payload:
            continue
        delay = request.form.get("delay" + suffix, "").strip()
        client_port = request.form.get("client_port" + suffix, "").strip()
        lanes.append((payload or "PING", delay, client_port))
    wait = request.form.get("wait", "10").strip()
    results = run_tests(lanes, wait)
    with _last_test_lock:
        _last_tests = results
    return redirect(url_for("index"))


def _run_lane(index, payload, delay_s, client_port_s, wait_s):
    try:
        wait = min(max(float(wait_s), 0.5), 60.0)
    except ValueError:
        wait = 10.0
    wire = payload
    try:
        delay = float(delay_s)
        if delay > 0:
            wire = f"DELAY:{delay}:{payload}"  # 接收器识别的延迟回包指令
    except ValueError:
        pass
    data = wire.encode()
    result = {"lane": index, "time": fmt_ts(time.time()), "payload": wire, "ok": False,
              "reply": "", "error": "", "rtt": None, "client": "", "receiver": None,
              "observed_source_port": None, "forward_source_port": None,
              "mode": None, "session_id": None}
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if client_port_s:
            sock.bind(("0.0.0.0", int(client_port_s)))
        sock.settimeout(wait)
        sock.connect(("127.0.0.1", UDP_LISTEN_PORT))
        result["client"] = fmt_addr(sock.getsockname())
        t0 = time.monotonic()
        sock.send(data)
        try:
            reply = sock.recv(65535)
            result["ok"] = True
            result["rtt"] = round(time.monotonic() - t0, 3)
            result["reply"] = preview(reply)
        except socket.timeout:
            result["error"] = f"等待回包超时（{wait}s）"
    except Exception as exc:
        result["error"] = f"发送失败：{exc}"
    finally:
        sock.close()
    time.sleep(0.1)  # 等代理把回包/日志处理完
    if result["client"]:
        info = state.client_info(result["client"])
        if info:
            result["receiver"] = info["receiver"]
            result["observed_source_port"] = info["observed_source_port"]
            result["forward_source_port"] = info["upstream_port"]
            result["mode"] = info["mode"]
            result["session_id"] = info["session_id"]
        if result["receiver"] is None:
            result["receiver"] = store.latest_receiver_for_client(result["client"])
    return result


def run_tests(lanes, wait_s):
    """并行发送多路试传报文（各自独立 UDP 套接字），返回各自结果。"""
    results = [None] * len(lanes)
    threads = []
    for i, (payload, delay, port) in enumerate(lanes):
        t = threading.Thread(target=lambda i=i, p=payload, d=delay, cp=port:
                             results.__setitem__(i, _run_lane(i + 1, p, d, cp, wait_s)))
        t.start()
        threads.append(t)
    for t in threads:
        t.join()
    return [r for r in results if r is not None]


def run_test(payload, delay_s, client_port_s, wait_s):
    """兼容旧接口：单路试传。"""
    return run_tests([(payload, delay_s, client_port_s)], wait_s)[0]


# ---------------- 启动：asyncio 线程 + Flask 主线程 ----------------
def _run_loop():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    state.loop = loop
    loop.run_until_complete(state.start())
    loop.run_forever()


def main():
    t = threading.Thread(target=_run_loop, name="udp-proxy-loop", daemon=True)
    t.start()
    print(f"[proxy] 操作网页 http://{HTTP_HOST}:{HTTP_PORT}", flush=True)
    app.run(host=HTTP_HOST, port=HTTP_PORT, threaded=True, use_reloader=False)


if __name__ == "__main__":
    main()
