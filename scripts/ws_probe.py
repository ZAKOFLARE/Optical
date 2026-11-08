#!/usr/bin/env python3
"""最小 WebSocket 探针：验证"客户端发视角 → 服务端按视角推历史和排行榜"。

不依赖任何第三方库（远程机器上 websockets / websocket-client 都不一定有），
只用标准库手搓握手和帧解析。用法：

    python3 scripts/ws_probe.py http://127.0.0.1:19100 <session-cookie>

成功时打印 VIEW_OK 并以 0 退出，失败打印原因并以 1 退出。
"""

import base64
import hashlib
import json
import os
import socket
import struct
import sys

HOSTPORT = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:19100"
COOKIE = sys.argv[2] if len(sys.argv) > 2 else ""


def parse_url(url):
    rest = url.split("://", 1)[-1]
    host, _, port = rest.partition(":")
    return host or "127.0.0.1", int(port or 80)


def read_frame(sock):
    """读一个完整的 WebSocket 帧；服务端下发的帧不带 mask。"""
    hdr = b""
    while len(hdr) < 2:
        chunk = sock.recv(2 - len(hdr))
        if not chunk:
            raise EOFError("连接被关闭")
        hdr += chunk
    opcode = hdr[0] & 0x0F
    masked = bool(hdr[1] & 0x80)
    ln = hdr[1] & 0x7F
    if ln == 126:
        ln = struct.unpack(">H", sock.recv(2))[0]
    elif ln == 127:
        ln = struct.unpack(">Q", sock.recv(8))[0]
    mask = sock.recv(4) if masked else b""
    data = b""
    while len(data) < ln:
        chunk = sock.recv(ln - len(data))
        if not chunk:
            raise EOFError("帧被截断")
        data += chunk
    if masked:
        data = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
    return opcode, data


def send_text(sock, text):
    payload = text.encode()
    header = bytearray([0x81])  # FIN + text
    n = len(payload)
    if n < 126:
        header.append(0x80 | n)
    elif n < 65536:
        header.append(0x80 | 126)
        header += struct.pack(">H", n)
    else:
        header.append(0x80 | 127)
        header += struct.pack(">Q", n)
    mask = os.urandom(4)
    header += mask
    masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    sock.sendall(bytes(header) + masked)


def main():
    host, port = parse_url(HOSTPORT)
    key = base64.b64encode(os.urandom(16)).decode()
    req = (
        f"GET /api/ws HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        f"Upgrade: websocket\r\n"
        f"Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        f"Sec-WebSocket-Version: 13\r\n"
        f"Cookie: {COOKIE}\r\n\r\n"
    )
    sock = socket.create_connection((host, port), timeout=10)
    sock.sendall(req.encode())
    resp = b""
    while b"\r\n\r\n" not in resp:
        chunk = sock.recv(4096)
        if not chunk:
            break
        resp += chunk
    first_line = resp.split(b"\r\n")[0]
    if b"101" not in first_line:
        # 不要在 f-string 里写反斜杠：Python 3.11 及更早会直接语法错误
        print("握手失败: " + repr(first_line))
        return 1
    expect = base64.b64encode(
        hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()
    ).decode()
    if expect.encode() not in resp:
        print("Sec-WebSocket-Accept 不匹配")
        return 1

    # 先声明视角：按后端看、近 1 小时、只算 2xx
    send_text(
        sock,
        json.dumps(
            {
                "type": "view",
                "gran": 60,
                "range": 3600,
                "by": "backend",
                "limit": 5,
                "filters": [{"field": "status", "op": "eq", "value": "2xx"}],
            }
        ),
    )

    got_history = got_stats = got_config = got_apps = False
    deadline = 12
    sock.settimeout(1.0)
    for _ in range(deadline * 3):
        try:
            opcode, data = read_frame(sock)
        except socket.timeout:
            continue
        except EOFError as e:
            print(f"连接断开: {e}")
            return 1
        if opcode == 0x8:
            print("服务端主动关闭")
            return 1
        if opcode != 0x1:
            continue
        try:
            msg = json.loads(data)
        except Exception:
            continue
        if msg.get("type") != "snapshot":
            continue
        if "config" in msg and isinstance(msg.get("rev"), int):
            got_config = True
        # 应用状态必须走这条通道：前端不再单独 4 秒轮询 /api/apps
        if isinstance(msg.get("apps"), list):
            got_apps = True
            for a in msg["apps"]:
                if not isinstance(a.get("logs"), list):
                    print(f"应用状态缺 logs 字段: {a.get('name')}")
                    return 1
        if "history" in msg:
            got_history = msg["history"].get("gran_secs") == 60
        if "stats" in msg:
            st = msg["stats"]
            got_stats = (
                st.get("by") == "backend"
                and st.get("range_secs") == 3600
                and st.get("limit") == 5
                and st.get("filter_fields") == ["route", "backend", "host", "status"]
            )
        if got_history and got_stats and got_config:
            send_text(
                sock,
                json.dumps({"type": "view", "gran": 60, "range": 3600, "by": "ua", "limit": 0}),
            )
            sock.settimeout(2.0)
            for _ in range(20):
                try:
                    opcode, data = read_frame(sock)
                except socket.timeout:
                    continue
                if opcode != 0x1:
                    continue
                m2 = json.loads(data)
                st2 = m2.get("stats")
                if not st2:
                    continue
                if st2.get("limit") != 0:
                    print(f"limit=0 被改写成 {st2.get('limit')}，查看全部没生效")
                    return 1
                print("ALL_OK")
                break
            # 第三轮：写操作也必须走这条通道（命令 + 回执），不是只有推送
            send_text(sock, json.dumps({"type": "cmd", "id": "p1", "action": "cache.purge", "payload": {}}))
            sock.settimeout(2.0)
            for _ in range(20):
                try:
                    opcode, data = read_frame(sock)
                except socket.timeout:
                    continue
                if opcode != 0x1:
                    continue
                m3 = json.loads(data)
                if m3.get("type") != "reply" or m3.get("id") != "p1":
                    continue
                if not m3.get("ok"):
                    print(f"WS 命令回执失败: {m3.get('error')}")
                    return 1
                print("CMD_OK")
                break
            # 第四轮：只读接口也得走这条通道，不能有的页在 WS、有的页还在 HTTP
            send_text(sock, json.dumps({"type": "query", "id": "q1", "action": "tls"}))
            sock.settimeout(2.0)
            for _ in range(20):
                try:
                    opcode, data = read_frame(sock)
                except socket.timeout:
                    continue
                if opcode != 0x1:
                    continue
                mq = json.loads(data)
                if mq.get("type") != "reply" or mq.get("id") != "q1":
                    continue
                if not mq.get("ok"):
                    print(f"WS 查询回执失败: {mq.get('error')}")
                    return 1
                if "cert_path" not in (mq.get("data") or {}):
                    print("WS 查询 tls 返回结构不对")
                    return 1
                print("QUERY_OK")
                break

            print("APPS_OK" if got_apps else "APPS_MISSING")
            print("VIEW_OK")
            print(f"  history bucket_ms={msg['history']['bucket_ms']} points={len(msg['history']['points'])}")
            print(f"  stats rows={len(msg['stats']['rows'])} total={msg['stats']['total']}")
            # 这一帧可能只带 stats/history（没改配置就不推 config），别硬取
            if "rev" in msg:
                print(f"  config rev={msg['rev']} keys={len(msg.get('config') or {})}")
            return 0
    print(f"没等到完整快照 history={got_history} stats={got_stats} config={got_config} apps={got_apps}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
