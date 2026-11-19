#!/usr/bin/env python3
"""本地遥测接收器：原样回显报文，可延迟回包。

延迟来源（优先级从高到低）：
1. 报文以 "DELAY:<秒>:" 开头时，按该秒数延迟（回包仍包含完整原始报文）；
2. 否则用环境变量 REPLY_DELAY（秒，默认 0）。

固定源端口模式（ALLOW_SOURCE_PORT 设置后启用）：
- 只接收源端口等于 ALLOW_SOURCE_PORT 的来包，其余丢弃并记日志；
- 回包发回该来包的实际源 IP:端口（即代理的固定端口）；
- 若报文以 SESSION_TAG_MAGIC（默认 "TLM1"）+16 位十六进制会话标识
  开头，回包时把这 20 字节标识带回在回包最前面，代理据此把回包
  交给原会话；标识本身不属于终端报文，终端看不到（代理剥除）；
- 回包在标识后附带 "SRC" + 2 字节大端源端口，让代理/网页展示
  接收器实际观测到的代理源端口；代理剥除后再交给终端。
- 模式关闭时行为与原来完全一致：任何来源都接收，原样回显。

环境变量：
  RECEIVER_NAME     显示名（默认 receiver）
  LISTEN_PORT       监听端口（默认 9001）
  REPLY_DELAY       默认回包延迟秒数（默认 0）
  ALLOW_SOURCE_PORT 固定源端口（未设置/留空=不校验来源端口）
  SESSION_TAG_MAGIC 会话标识 magic（4 字节 ASCII，默认 TLM1）
"""

import asyncio
import os
import re
import struct

NAME = os.environ.get("RECEIVER_NAME", "receiver")
PORT = int(os.environ.get("LISTEN_PORT", "9001"))
DEFAULT_DELAY = float(os.environ.get("REPLY_DELAY", "0"))
MAX_DELAY = float(os.environ.get("MAX_DELAY", "60"))

_source_port_s = os.environ.get("ALLOW_SOURCE_PORT", "").strip()
ALLOW_SOURCE_PORT = int(_source_port_s) if _source_port_s else None
SESSION_TAG_MAGIC = os.environ.get("SESSION_TAG_MAGIC", "TLM1").encode()
assert len(SESSION_TAG_MAGIC) == 4, "SESSION_TAG_MAGIC 必须是 4 字节"
TAG_TOKEN_LEN = 16
TAG_LEN = len(SESSION_TAG_MAGIC) + TAG_TOKEN_LEN
SRC_HEADER = b"SRC"
_HEX = re.compile(rb"^[0-9a-fA-F]{%d}$" % TAG_TOKEN_LEN)

DELAY_RE = re.compile(rb"^DELAY:([0-9]+(?:\.[0-9]+)?):")


class ReceiverProtocol(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        tag = b""
        if ALLOW_SOURCE_PORT is not None:
            if addr[1] != ALLOW_SOURCE_PORT:
                print(f"[{NAME}] 丢弃来自 {addr[0]}:{addr[1]} 的报文：源端口不是约定端口 "
                      f"{ALLOW_SOURCE_PORT}", flush=True)
                return
            if len(data) >= TAG_LEN and data.startswith(SESSION_TAG_MAGIC) \
                    and _HEX.match(data[4:TAG_LEN]):
                tag, data = data[:TAG_LEN], data[TAG_LEN:]
        delay = DEFAULT_DELAY
        m = DELAY_RE.match(data)
        if m:
            delay = min(float(m.group(1)), MAX_DELAY)
        print(f"[{NAME}] 收到 {len(data)}B 来自 {addr[0]}:{addr[1]}"
              f"{'，会话标识 ' + tag[4:].decode() if tag else ''}，{delay}s 后回包", flush=True)
        asyncio.get_running_loop().call_later(delay, self._reply, data, addr, tag)

    def _reply(self, data, addr, tag=b""):
        try:
            wire = data
            if tag:
                # 标识 + 接收器观测到的源端口 + 原始回包
                wire = tag + SRC_HEADER + struct.pack("!H", addr[1]) + data
            self.transport.sendto(wire, addr)
            print(f"[{NAME}] 已回包 {len(data)}B 到 {addr[0]}:{addr[1]}", flush=True)
        except Exception as exc:
            print(f"[{NAME}] 回包失败: {exc}", flush=True)


async def main():
    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(
        lambda: ReceiverProtocol(), local_addr=("0.0.0.0", PORT)
    )
    mode = (f"固定源端口模式，只接收源端口 {ALLOW_SOURCE_PORT} 的报文"
            if ALLOW_SOURCE_PORT is not None else "不校验来源端口")
    print(f"[{NAME}] UDP 监听 0.0.0.0:{PORT}，默认延迟 {DEFAULT_DELAY}s，{mode}", flush=True)
    await asyncio.Event().wait()


if __name__ == "__main__":
    asyncio.run(main())
