#!/usr/bin/env python3
"""固定源端口模式端到端验证（不依赖 Docker）。

用法：python3 scripts/verify_fixed_mode.py

覆盖：启用/关闭开关、两路终端同报文/回包乱序按会话交付、接收器只收约定源端口、
1400 字节上限、A/B 切换只影响新会话、过期/重启后旧回包不投递、
固定端口被占用时网页报错且不换端口转发、网页并行两路试传展示实际源端口、
关闭模式后沿用原转发方式。
"""

import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROXY_PY = os.path.join(ROOT, "proxy", "app.py")
RECEIVER_PY = os.path.join(ROOT, "receiver", "receiver.py")

UDP_PORT = 19100
HTTP_PORT = 18180
FIXED_PORT = 19500
MAX_SIZE = 1400
RECV_A_PORT, RECV_B_PORT = 19201, 19202          # 校验来源端口的接收器
OPEN_A_PORT, OPEN_B_PORT = 19301, 19302          # 不校验来源端口的接收器

_failures = []


def check(name, cond, detail=""):
    mark = "PASS" if cond else "FAIL"
    print(f"[{mark}] {name}" + (f"  -- {detail}" if detail and not cond else ""))
    if not cond:
        _failures.append(name)


def http_get(base, path):
    with urllib.request.urlopen(base + path, timeout=10) as r:
        return json.load(r)


def http_post(base, path, data):
    with urllib.request.urlopen(
        base + path, data=urllib.parse.urlencode(data).encode(), timeout=60
    ) as r:
        return r.status


def wait_http_up(base, timeout=20):
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            http_get(base, "/api/state")
            return True
        except Exception:
            time.sleep(0.3)
    return False


def udp_client(proxy_port=UDP_PORT, bind_port=0):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if bind_port:
        s.bind(("127.0.0.1", bind_port))
    s.connect(("127.0.0.1", proxy_port))
    return s


def send_recv(sock, payload, timeout=5.0):
    sock.settimeout(timeout)
    sock.send(payload)
    return sock.recv(65535)


def start_receiver(name, port, logdir, allow_source_port=None):
    env = dict(os.environ, RECEIVER_NAME=name, LISTEN_PORT=str(port), REPLY_DELAY="0")
    if allow_source_port:
        env["ALLOW_SOURCE_PORT"] = str(allow_source_port)
    log = open(os.path.join(logdir, f"receiver-{name}-{port}.log"), "w")
    p = subprocess.Popen([sys.executable, RECEIVER_PY], env=env,
                         stdout=log, stderr=subprocess.STDOUT)
    return p


def start_proxy(db_path, logdir, tag, a_port=RECV_A_PORT, b_port=RECV_B_PORT,
                udp_port=UDP_PORT, http_port=HTTP_PORT, fixed_port=FIXED_PORT,
                enabled=False):
    env = dict(
        os.environ,
        UDP_LISTEN_PORT=str(udp_port), HTTP_PORT=str(http_port),
        RECEIVER_A_HOST="127.0.0.1", RECEIVER_A_PORT=str(a_port),
        RECEIVER_B_HOST="127.0.0.1", RECEIVER_B_PORT=str(b_port),
        SESSION_IDLE_TIMEOUT="5", DB_PATH=db_path,
        FIXED_SOURCE_PORT_ENABLED="1" if enabled else "0",
        FIXED_SOURCE_PORT=str(fixed_port),
        MAX_FORWARD_SIZE=str(MAX_SIZE),
    )
    log = open(os.path.join(logdir, f"proxy-{tag}.log"), "w")
    p = subprocess.Popen([sys.executable, PROXY_PY], env=env,
                         stdout=log, stderr=subprocess.STDOUT)
    return p, f"http://127.0.0.1:{http_port}"


def stop(p):
    p.terminate()
    try:
        p.wait(timeout=8)
    except Exception:
        p.kill()


def main():
    tmp = tempfile.mkdtemp(prefix="proxy-fixed-verify-")
    db_path = os.path.join(tmp, "proxy.db")
    procs = []
    procs.append(start_receiver("A", RECV_A_PORT, tmp, FIXED_PORT))
    procs.append(start_receiver("B", RECV_B_PORT, tmp, FIXED_PORT))
    procs.append(start_receiver("A", OPEN_A_PORT, tmp))
    procs.append(start_receiver("B", OPEN_B_PORT, tmp))
    proxy, base = start_proxy(db_path, tmp, "fixed")
    procs.append(proxy)
    try:
        if not wait_http_up(base):
            check("代理启动", False, f"日志见 {tmp}")
            return 1
        print(f"--- 环境就绪（日志目录 {tmp}）---")

        st = http_get(base, "/api/state")
        check("默认关闭固定源端口模式", st["fixed"]["active"] is False, str(st["fixed"]))

        # 1. 接收器拒绝非约定源端口
        direct = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        direct.settimeout(1.0)
        direct.sendto(b"direct-bypass", ("127.0.0.1", RECV_A_PORT))
        rejected = False
        try:
            direct.recv(65535)
            direct.settimeout(1.0)
        except socket.timeout:
            rejected = True
        direct.close()
        check("接收器不应答非约定源端口", rejected)

        # 2. 启用固定源端口模式
        http_post(base, "/mode", {"action": "enable"})
        f = http_get(base, "/api/state")["fixed"]
        check("启用固定源端口模式", f["active"] and f["port"] == FIXED_PORT, str(f))
        check("启用后旧会话已清空", http_get(base, "/api/state")["sessions"] == [])

        # 3. 两路终端发完全相同的报文，回包按会话交付
        same1, same2 = udp_client(), udp_client()
        same_payload = b"IDENTICAL-PAYLOAD"
        r1 = send_recv(same1, same_payload)
        r2 = send_recv(same2, same_payload)
        check("相同报文两路都原样收回", r1 == same_payload and r2 == same_payload,
              f"{r1!r} {r2!r}")
        time.sleep(0.3)
        msgs = http_get(base, "/api/state")["messages"]
        per_client = {}
        for sock in (same1, same2):
            client = f"127.0.0.1:{sock.getsockname()[1]}"
            c2r = [m for m in msgs if m["client"] == client
                   and m["direction"] == "客户端→接收器"]
            r2c = [m for m in msgs if m["client"] == client
                   and m["direction"] == "接收器→客户端"]
            per_client[client] = (c2r[0]["session_id"] if c2r else None,
                                  r2c[0]["session_id"] if r2c else None)
        check("相同报文各自归属自己的会话",
              all(a is not None and a == b for a, b in per_client.values())
              and len({a for a, _ in per_client.values()}) == 2, str(per_client))
        same1.close()
        same2.close()

        # 4. 回包乱序：延迟 2s 的会话的回包不得送进延迟 0.3s 的会话
        c1 = udp_client()
        c2 = udp_client()
        res = {}

        def lane(sock, delay, tag):
            wire = f"DELAY:{delay}:{tag}".encode()
            t0 = time.monotonic()
            try:
                sock.settimeout(8)
                sock.send(wire)
                reply = sock.recv(65535)
                res[sock] = (reply, time.monotonic() - t0)
            except Exception as exc:
                res[sock] = (repr(exc).encode(), time.monotonic() - t0)

        t1 = threading.Thread(target=lane, args=(c1, 2.0, "SLOW"))
        t2 = threading.Thread(target=lane, args=(c2, 0.3, "FAST"))
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        check("乱序回包各归各会话",
              res[c1][0] == b"DELAY:2.0:SLOW" and res[c1][1] >= 1.5
              and res[c2][0] == b"DELAY:0.3:FAST" and res[c2][1] < 1.5, str(res))
        time.sleep(0.3)
        snap = {s["client"]: s for s in http_get(base, "/api/state")["sessions"]}
        s1 = snap.get(f"127.0.0.1:{c1.getsockname()[1]}")
        s2 = snap.get(f"127.0.0.1:{c2.getsockname()[1]}")
        check("两会话都从固定端口发出且接收器观测一致",
              s1 and s2 and s1["mode"] == s2["mode"] == "固定端口"
              and s1["source_port"] == s2["source_port"] == FIXED_PORT, f"{s1} {s2}")

        # 5. 1400 字节上限
        c3 = udp_client()
        check("1400 字节报文可转发", send_recv(c3, b"x" * MAX_SIZE) == b"x" * MAX_SIZE)
        c3.send(b"y" * (MAX_SIZE + 1))
        over = True
        try:
            c3.settimeout(2.0)
            c3.recv(65535)
            over = False
        except socket.timeout:
            pass
        check("超过 1400 字节的报文被丢弃", over)
        time.sleep(0.3)
        drop = [m for m in http_get(base, "/api/state")["messages"]
                if m["direction"] == "丢弃" and str(MAX_SIZE + 1) in m["note"]]
        check("超限丢弃有日志", bool(drop), str(drop[:2]))
        c3.close()

        # 6. A/B 切换只影响新会话
        http_post(base, "/switch", {"target": "B"})
        check("切换后目标为 B", http_get(base, "/api/state")["target"] == "B")
        check("旧会话仍从固定端口走 A", send_recv(c1, b"stick-A") == b"stick-A")
        time.sleep(0.2)
        e = [m for m in http_get(base, "/api/state")["messages"]
             if m["client"] == f"127.0.0.1:{c1.getsockname()[1]}"
             and m["direction"] == "客户端→接收器" and "stick-A" in m["payload"]]
        check("切换后旧会话仍走接收器 A", bool(e) and e[0]["receiver"] == "A", str(e))
        c4 = udp_client()
        check("新会话报文有回包", send_recv(c4, b"new-B") == b"new-B")
        time.sleep(0.2)
        e = [m for m in http_get(base, "/api/state")["messages"]
             if m["client"] == f"127.0.0.1:{c4.getsockname()[1]}"
             and m["direction"] == "客户端→接收器" and "new-B" in m["payload"]]
        check("新会话走接收器 B", bool(e) and e[0]["receiver"] == "B", str(e))
        c4.close()
        c1.close()
        c2.close()

        # 7. 会话过期后旧回包不投递（终端用原端口重连）
        c5 = udp_client()
        t0 = time.time()
        c5.send(b"DELAY:7:late-fixed")
        time.sleep(6)
        c5.send(b"fresh-after-expiry")
        late = False
        while time.time() < t0 + 9:
            c5.settimeout(0.2)
            try:
                if b"late-fixed" in c5.recv(65535):
                    late = True
            except socket.timeout:
                pass
        check("过期后同端口重连收不到旧回包", not late)
        time.sleep(0.3)
        drop = [m for m in http_get(base, "/api/state")["messages"]
                if m["direction"] == "丢弃" and "无对应会话" in m["note"]]
        check("旧会话回包按标识失效丢弃并记日志", bool(drop), str(drop[:2]))
        c5.close()

        # 8. 网页并行两路试传：不同延迟、实际接收器与观测源端口
        http_post(base, "/test", {"payload": "WEB-1", "delay": "1.5", "client_port": "",
                                  "payload2": "WEB-2", "delay2": "0", "client_port2": "",
                                  "wait": "10"})
        time.sleep(0.3)
        lt = http_get(base, "/api/state")["last_tests"]
        check("网页两路试传都有结果", len(lt) == 2, str(lt))
        by_lane = {x["lane"]: x for x in lt}
        check("第 1 路回包正确", by_lane.get(1, {}).get("reply") == "DELAY:1.5:WEB-1",
              str(by_lane.get(1)))
        check("第 2 路回包正确", by_lane.get(2, {}).get("reply") == "WEB-2",
              str(by_lane.get(2)))
        check("两路都显示实际接收器 B",
              by_lane[1]["receiver"] == "B" and by_lane[2]["receiver"] == "B", str(by_lane))
        check("两路都显示接收器观测到的固定源端口",
              by_lane[1]["observed_source_port"] == FIXED_PORT
              and by_lane[2]["observed_source_port"] == FIXED_PORT, str(by_lane))
        check("两路并行、第 1 路有延迟",
              by_lane[1]["rtt"] >= 1.3 and by_lane[2]["rtt"] < 1.3, str(by_lane))

        # 9. 代理重启：固定模式保留，旧回包仍不投递
        c6 = udp_client()
        c6.send(b"DELAY:6:pre-restart")
        time.sleep(0.5)
        stop(proxy)
        proxy, base = start_proxy(db_path, tmp, "fixed-restart")
        procs.append(proxy)
        check("重启后代理恢复", wait_http_up(base))
        check("重启后固定源端口模式保留", http_get(base, "/api/state")["fixed"]["active"])
        c6.settimeout(1.0)
        fresh = b""
        c6.send(b"post-restart-fresh")
        end = time.time() + 5
        while time.time() < end:
            try:
                reply = c6.recv(65535)
            except socket.timeout:
                continue
            if b"post-restart-fresh" in reply:
                fresh = reply
            elif b"pre-restart" in reply:
                check("重启后旧会话回包未送达", False, reply)
        check("重启后同端口重连收到新会话回包", fresh == b"post-restart-fresh")
        c6.close()

        # 10. 固定端口被占用：网页报错，且不换端口转发
        blocker = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        blocker.bind(("0.0.0.0", 19501))
        procs.append(start_receiver("A", 19401, tmp, 19501))
        procs.append(start_receiver("B", 19402, tmp, 19501))
        db2 = os.path.join(tmp, "proxy2.db")
        proxy2, base2 = start_proxy(db2, tmp, "occupied", a_port=19401, b_port=19402,
                                    udp_port=19200, http_port=18280,
                                    fixed_port=19501, enabled=True)
        procs.append(proxy2)
        if not wait_http_up(base2):
            check("占用测试代理启动", False)
        else:
            st = http_get(base2, "/api/state")
            check("固定端口被占用时启用失败",
                  st["fixed"]["active"] is False and "绑定失败" in st["fixed"]["error"],
                  str(st["fixed"]))
            page = urllib.request.urlopen(base2 + "/", timeout=5).read().decode("utf-8")
            check("网页显示固定端口错误", "绑定失败" in page)
            c7 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            c7.settimeout(1.5)
            c7.sendto(b"must-not-forward", ("127.0.0.1", 19200))
            no_reply = False
            try:
                c7.recv(65535)
            except socket.timeout:
                no_reply = True
            c7.close()
            check("端口占用时代理不换端口转发", no_reply)
            time.sleep(0.3)
            drop = [m for m in http_get(base2, "/api/state")["messages"]
                    if m["direction"] == "丢弃" and "固定源端口模式不可用" in m["note"]]
            check("端口占用时丢弃有日志", bool(drop), str(drop[:2]))
            blocker.close()
            blocker = None
            http_post(base2, "/mode", {"action": "enable"})
            st = http_get(base2, "/api/state")
            check("释放端口后可启用", st["fixed"]["active"], str(st["fixed"]))
            c8 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            c8.settimeout(5)
            c8.sendto(b"after-free", ("127.0.0.1", 19200))
            check("释放端口后正常转发", c8.recv(65535) == b"after-free")
            c8.close()
        if blocker is not None:
            blocker.close()
        stop(proxy2)

        # 11. 关闭固定源端口模式，沿用原来的转发方式（每会话独立上游端口）
        http_post(base, "/mode", {"action": "disable"})
        st = http_get(base, "/api/state")
        check("关闭固定源端口模式",
              st["fixed"]["active"] is False and not st["fixed"]["requested"])
        check("关闭后会话已清空", st["sessions"] == [])
        stop(proxy)
        procs.remove(proxy)
        # 原转发方式下接收器不校验来源端口：换用不校验的接收器继续验证
        proxy, base = start_proxy(db_path, tmp, "closed", a_port=OPEN_A_PORT,
                                  b_port=OPEN_B_PORT)
        procs.append(proxy)
        check("关闭模式代理恢复", wait_http_up(base))
        check("重启后仍为关闭模式", http_get(base, "/api/state")["fixed"]["active"] is False)
        c9 = udp_client()
        check("关闭后报文仍原样回传", send_recv(c9, b"plain-again") == b"plain-again")
        time.sleep(0.2)
        sess = [s for s in http_get(base, "/api/state")["sessions"]
                if s["client"] == f"127.0.0.1:{c9.getsockname()[1]}"]
        check("关闭后恢复每会话独立上游端口",
              bool(sess) and sess[0]["mode"] == "独立端口"
              and sess[0]["source_port"] != FIXED_PORT, str(sess))
        c9.close()

    finally:
        for p in procs:
            try:
                stop(p)
            except Exception:
                pass

    print("---")
    if _failures:
        print(f"共 {len(_failures)} 项失败: {_failures}")
        return 1
    print("固定源端口模式验证全部通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
