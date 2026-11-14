#!/usr/bin/env bash
# Optical 端到端验证：转发 / 路由 / 后端池 / 缓存 / WAF 九族 / TLS / WS / 认证 / 回溯 / 审计
#
# 用法：cargo build --release && ./scripts/smoke.sh
#       BIN=./target/debug/optical ./scripts/smoke.sh
# 依赖：curl、python3（仅用于改 JSON）

set -uo pipefail

BIN="${BIN:-./target/release/optical}"
GW="127.0.0.1:18080"
ADM="127.0.0.1:19100"
TLS="127.0.0.1:18443"
UP1="127.0.0.1:18081"
UP2="127.0.0.1:18082"
TMP="$(mktemp -d)"
CFG="$TMP/optical.toml"
TOKEN="$TMP/optical.token"
PASSWD="smoke-pass-123"
PASS=0
FAIL=0
COOKIE=""

cleanup() {
  for pid in ${PIDS:-}; do kill "$pid" 2>/dev/null; done
  wait 2>/dev/null
  rm -rf "$TMP"
}
trap cleanup EXIT
PIDS=""

check() {
  local name="$1" want="$2" got="$3"
  if printf '%s' "$got" | grep -q -- "$want"; then
    printf '  \033[32mPASS\033[0m %s\n' "$name"; PASS=$((PASS+1))
  else
    printf '  \033[31mFAIL\033[0m %s\n        期望包含: %s\n        实际: %s\n' "$name" "$want" "$(printf '%s' "$got" | head -c 240)"
    FAIL=$((FAIL+1))
  fi
}

wait_http() {
  local url="$1" n="${2:-60}"
  for _ in $(seq 1 "$n"); do
    if curl -sf -m 1 "$url" >/dev/null 2>&1; then return 0; fi
    sleep 0.25
  done
  return 1
}

code() { curl -s -o /dev/null -w '%{http_code}' -m 6 "$@"; }

echo
echo "== Optical smoke test v0.2 =="
echo "   bin: $BIN"
echo "   cfg: $CFG"
echo

[ -x "$BIN" ] || { echo "找不到可执行文件：$BIN（先 cargo build）"; exit 1; }

# ---------- 配置 ----------
cat > "$CFG" <<EOF
[server]
listen = "$GW"
admin_listen = "$ADM"
default_upstream = "http://$UP1"
request_timeout_ms = 8000
log_level = "info"
max_inspect_bytes = 8192
server_header = "optical-smoke"

[tls]
enabled = true
listen = "$TLS"
min_version = "1.2"

# 自定义规则：命中后要能出现在分析里（by=rule）
[[rules]]
name = "smoke-rule"
[[rules.matches]]
kind = "path"
op = "prefix"
value = "/rule-hit"

[admin]
enabled = true
username = "admin"
session_ttl_secs = 3600
max_failed_attempts = 5

[cache]
enabled = true
ttl_secs = 30
max_bytes = 1048576
max_entries = 64
cacheable_status = [200]
cacheable_exts = [".css", ".js"]

[storage]
config_history_keep = 5
config_history_max_bytes = 262144
config_history_keep_days = 7
audit_enabled = true
audit_keep = 200
audit_max_bytes = 262144

[metrics]
top_n = 5
history_points = 2400

# 非固化路径：所有落盘位置挪到 <cfg_dir>/data
[paths]
data_dir = "data"

# 错误页：目录下的 502.html 必须优先于内置模板
[error_pages]
enabled = true
footer = "SMOKE-FOOTER"

[waf]
enabled = true
mode = "block"
score_threshold = 4

[waf.dos]
enabled = true
max_body_bytes = 65536
conn_per_ip = 200
conn_burst_per_sec = 200

[[header_rules]]
phase = "response"
action = "set"
name = "X-Smoke"
value = "1"

[[backend_groups]]
name = "app"
note = "主应用组"
strategy = "wrr"

[[backend_groups]]
name = "api"
note = "API 组"
strategy = "rr"

[[backends]]
name = "app-1"
url = "http://$UP1"
group = "app"
note = "主节点"
weight = 2
health_path = "/health"
health_interval_secs = 2

[[backends]]
name = "app-2"
url = "http://$UP2"
group = "app"
note = "备节点"
weight = 1
health_path = "/health"
health_interval_secs = 2

[[backends]]
name = "api-1"
url = "http://$UP2"
group = "api"
note = "API 节点"
weight = 1
health_path = "/health"
health_interval_secs = 2

[[routes]]
name = "api"
host = "*"
path_prefix = "/api"
upstream = ""
backend_group = "api"
strip_prefix = true
rewrite_host = true

[[routes]]
name = "web"
host = "*"
path_prefix = "/web"
upstream = ""
backend_group = "app"

# 单后端路由：即使同组另一台健康，也必须稳定落在一台上（防跨组/跨成员乱窜）
[[routes]]
name = "solo"
host = "*"
path_prefix = "/solo"
upstream = ""
backend = "app-1"

# 故意指向没人监听的端口，用来验证自定义错误页
[[routes]]
name = "dead"
host = "*"
path_prefix = "/dead"
upstream = "http://127.0.0.1:9"
EOF

mkdir -p "$TMP/data/error-pages"
cat > "$TMP/data/error-pages/502.html" <<'HTML'
<!DOCTYPE html><html><body><h1>SMOKE-CUSTOM-502</h1><p>{{status}} {{reason}}</p><p>{{message}}</p><footer>{{footer}}</footer></body></html>
HTML

"$BIN" --config "$CFG" passwd "$PASSWD" --write >/dev/null 2>&1 || true

# ---------- 上游 ----------
"$BIN" upstream-echo --listen "$UP1" >"$TMP/up1.log" 2>&1 & PIDS="$PIDS $!"
"$BIN" upstream-echo --listen "$UP2" >"$TMP/up2.log" 2>&1 & PIDS="$PIDS $!"
wait_http "http://$UP1/health" 40 || { echo "上游1未就绪"; cat "$TMP/up1.log"; exit 1; }
wait_http "http://$UP2/health" 40 || { echo "上游2未就绪"; cat "$TMP/up2.log"; exit 1; }

# ---------- 网关 ----------
"$BIN" run --config "$CFG" >"$TMP/gw.log" 2>&1 & PIDS="$PIDS $!"
wait_http "http://$ADM/api/health" 80 || { echo "网关未就绪"; cat "$TMP/gw.log"; exit 1; }
sleep 0.6

echo "-- 管理面认证 --"
check "无 Cookie 访问 /api/status 返回 401" '401' "$(code "http://$ADM/api/status")"
check "错误口令被拒" '"ok":false' "$(curl -s -m 6 -X POST "http://$ADM/api/auth/login" -H 'content-type: application/json' -d "{\"username\":\"admin\",\"password\":\"wrong\"}")"
LOGIN="$(curl -s -m 6 -D "$TMP/hdr.txt" -X POST "http://$ADM/api/auth/login" -H 'content-type: application/json' -d "{\"username\":\"admin\",\"password\":\"$PASSWD\"}")"
check "正确口令登录成功" '"ok":true' "$LOGIN"
COOKIE="$(grep -i '^set-cookie:' "$TMP/hdr.txt" | sed 's/^[Ss]et-[Cc]ookie: //' | cut -d';' -f1 | tr -d '\r')"
check "下发会话 Cookie" 'optical_sid=' "$COOKIE"
AUTH=(-H "cookie: $COOKIE")
check "带 Cookie 访问 /api/status" '"ok":true' "$(curl -s -m 6 "${AUTH[@]}" "http://$ADM/api/status")"

echo "-- 基础转发 / 路由 / 后端池 --"
check "默认上游转发" '"path":"/hello"' "$(curl -s -m 6 "http://$GW/hello?x=1")"
check "路由命中并剥离前缀" '"path":"/v1/ping"' "$(curl -s -m 6 "http://$GW/api/v1/ping")"
HDR="$(curl -si -m 6 "http://$GW/api/v1/ping" | tr -d '\r')"
check "响应头 x-optical-route: api" 'x-optical-route: api' "$HDR"
check "响应头指向后端池上游" "x-optical-upstream: $UP2" "$HDR"
check "响应头标记实际后端" 'x-optical-backend: api-1' "$HDR"
check "响应头标记负载均衡策略" 'x-optical-lb: rr' "$HDR"
check "转发响应带统一 Server 头" 'server: optical-smoke' "$HDR"
BE_UP=no
for _ in $(seq 1 20); do
  if curl -s -m 6 "${AUTH[@]}" "http://$ADM/api/backends" | grep -q '"healthy":true'; then BE_UP=yes; break; fi
  sleep 0.5
done
check "后端池探活标记 up（异步，最多等 10s）" 'yes' "$BE_UP"

echo "-- 分组负载均衡 / 错误页 / 非固化路径 --"
WEB_BE="$(for _ in $(seq 1 24); do curl -si -m 3 "http://$GW/web/x" | tr -d '\r' | grep -i '^x-optical-backend:' | awk '{print $2}'; done | sort | uniq -c)"
check "分组内两台都被轮询到（app-1）" 'app-1' "$WEB_BE"
check "分组内两台都被轮询到（app-2）" 'app-2' "$WEB_BE"
check "分组请求绝不落到别组（无 api-1）" '^0$' "$(printf '%s' "$WEB_BE" | grep -c 'api-1' || true)"
SOLO="$(for _ in $(seq 1 12); do curl -si -m 3 "http://$GW/solo/x" | tr -d '\r' | grep -i '^x-optical-backend:' | awk '{print $2}'; done | sort -u)"
check "单后端路由稳定命中 app-1" 'app-1' "$SOLO"
check "单后端路由不串到 app-2" '^0$' "$(printf '%s' "$SOLO" | grep -c 'app-2' || true)"
ERR_BODY="$(curl -s -m 6 "http://$GW/dead/x")"
check "502 使用自定义错误页" 'SMOKE-CUSTOM-502' "$ERR_BODY"
check "错误页模板占位符已替换" 'Bad Gateway' "$ERR_BODY"
check "错误页 footer 已替换" 'SMOKE-FOOTER' "$ERR_BODY"
check "错误页响应不可缓存" 'no-store' "$(curl -si -m 6 "http://$GW/dead/x" | tr -d '\r' | grep -i '^cache-control:')"
check "错误页响应也有统一 Server 头" 'server: optical-smoke' "$(curl -si -m 6 "http://$GW/dead/x" | tr -d '\r')"
check "status 暴露解析后的 data_dir" '/data"' "$(curl -s -m 6 "${AUTH[@]}" "http://$ADM/api/status")"
check "backends API 返回分组视图" '"groups":\[' "$(curl -s -m 6 "${AUTH[@]}" "http://$ADM/api/backends")"
check "分组视图含成员数" '"members":' "$(curl -s -m 6 "${AUTH[@]}" "http://$ADM/api/backends")"

echo "-- 缓存 --"
curl -s -o /dev/null -m 6 "http://$GW/assets/app.css"
check "第二次请求命中缓存" 'x-optical-cache: HIT' "$(curl -si -m 6 "http://$GW/assets/app.css" | tr -d '\r')"
check "缓存命中计数" '"cache_hit_rate"' "$(curl -s -m 6 "${AUTH[@]}" "http://$ADM/api/metrics")"

echo "-- 响应压缩（gzip / brotli）--"
# 造一个够大的响应体，跨过 compression.min_bytes（默认 512）
BIG="$(python3 -c "print('x' * 2000)")"
HDR() { curl -s -D - -o /dev/null -m 8 -H "$1" "http://$GW/hello?big=$BIG" | tr -d '\r' | tr 'A-Z' 'a-z'; }
H_GZ="$(HDR 'Accept-Encoding: gzip')"
check "gzip：响应带 content-encoding" 'content-encoding: gzip' "$H_GZ"
check "gzip：Vary 带上 accept-encoding（CDN 才不会串味）" 'vary: .*accept-encoding' "$H_GZ"
# hyper 会按实际 body 重算 Content-Length，所以"必须没有这个头"是错的期待；
# 要断言的是"声明值 = 实际压缩后的字节数"。
CL="$(printf '%s' "$H_GZ" | awk -F': *' '/^content-length/{print $2}' | tr -d ' \r')"
BL="$(curl -s -m 8 -H 'Accept-Encoding: gzip' "http://$GW/hello?big=$BIG" | wc -c | tr -d ' ')"
check "gzip：声明的长度就是压缩后的字节数" 'yes' "$([ -n "$CL" ] && [ "$CL" = "$BL" ] && echo yes || echo "no($CL/$BL)")"
H_BR="$(HDR 'Accept-Encoding: br, gzip')"
check "br：两种都支持时优先 brotli" 'content-encoding: br' "$H_BR"
check "br;q=0 是明确拒绝，退回 gzip" 'content-encoding: gzip' "$(HDR 'Accept-Encoding: br;q=0, gzip')"
check "客户端不接受压缩时不压" 'yes' \
  "$(printf '%s' "$(HDR 'Accept-Encoding: identity')" | grep -q 'content-encoding' && echo no || echo yes)"
# 压出来的东西必须真能解开，否则等于把页面弄坏
check "gzip 解压后仍是原文" '"service":"optical-echo"' \
  "$(curl -s -m 8 -H 'Accept-Encoding: gzip' "http://$GW/hello?big=$BIG" | python3 -c 'import sys,gzip;sys.stdout.write(gzip.decompress(sys.stdin.buffer.read()).decode())')"
# 解压校验：装了解码器才验，没有就明说跳过——不拿"编好的期望值"充数
if python3 -c 'import brotli' 2>/dev/null; then
  check "br 解压后仍是原文" '"service":"optical-echo"' \
    "$(curl -s -m 8 -H 'Accept-Encoding: br' "http://$GW/hello?big=$BIG" | python3 -c 'import sys,brotli;sys.stdout.write(brotli.decompress(sys.stdin.buffer.read()).decode())')"
else
  printf '  \033[33mSKIP\033[0m br 解压校验（本机 python 没有 brotli 模块，头部断言已覆盖）\n'
fi

echo "-- WAF --"
check "SQL 注入被拦" '403' "$(code "http://$GW/search?q=%27%20or%201%3D1%20union%20select%20pw")"
check "命中规则写入响应头" 'x-optical-waf: sql' "$(curl -si -m 6 "http://$GW/search?q=%27%20or%201%3D1" | tr -d '\r' | grep -i 'x-optical-waf')"
check "路径穿越被拦" '403' "$(code "http://$GW/static/%2e%2e%2f%2e%2e%2fetc%2fpasswd")"
check "SSRF 元数据地址被拦" '403' "$(code "http://$GW/fetch?url=http%3A%2F%2F169.254.169.254%2Flatest")"
check "JWT alg=none 被拦" '403' "$(code -H 'authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhIn0.' "http://$GW/me")"
check "参数污染被拦" '403' "$(code "http://$GW/pay?amount=1&amount=9999")"
check "开放重定向被拦" '403' "$(code "http://$GW/login?next=https%3A%2F%2Fevil.example")"
check "缓存欺骗被拦" '403' "$(code "http://$GW/user/42/profile.css")"
check "XXE 请求体被拦" '403' "$(curl -s -o /dev/null -w '%{http_code}' -m 6 -X POST "http://$GW/xml" -H 'content-type: application/xml' --data-binary '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>')"
check "超大请求体被拦（413）" '413' "$(head -c 70000 /dev/zero | tr '\0' 'a' | curl -s -o /dev/null -w '%{http_code}' -m 6 -X POST --data-binary @- "http://$GW/upload")"
check "正常请求不受影响" '"service":"optical-echo"' "$(curl -s -m 6 "http://$GW/ok?q=hello")"
check "帧限制头已注入" 'x-frame-options: DENY' "$(curl -si -m 6 "http://$GW/ok" | tr -d '\r')"
check "自定义头改写生效" 'x-smoke: 1' "$(curl -si -m 6 "http://$GW/ok" | tr -d '\r')"

echo "-- WebSocket 隧道 --"
check "WS 升级返回 101" '101' "$(curl -si -m 3 -H 'Connection: Upgrade' -H 'Upgrade: websocket' \
  -H 'Sec-WebSocket-Version: 13' -H 'Sec-WebSocket-Key: x3JJHMbDL1EzLkh9GBhXDw==' "http://$GW/ws" \
  | tr -d '\r' | head -1)"

echo "-- TLS 1.2/1.3 --"
check "HTTPS 握手并转发" '"service":"optical-echo"' "$(curl -sk -m 6 "https://$TLS/hello")"
check "TLS1.2 客户端可握手（min=1.2）" '200' "$(code -k --tls-max 1.2 "https://$TLS/hello")"
check "TLS 握手计数已统计" '"tls_handshakes"' "$(curl -s -m 6 "${AUTH[@]}" "http://$ADM/api/metrics")"

echo "-- 证书上传（网关只挂证书，不签发） --"
# 上传接口的入参是一对现成的 PEM，用 python 拼 JSON 比在 shell 里转义换行靠谱
up_json() {
  python3 - "$1" "$2" <<'PY'
import json, sys
print(json.dumps({"cert": open(sys.argv[1]).read(), "key": open(sys.argv[2]).read()}))
PY
}
up_post() {
  curl -s -m 8 "${AUTH[@]}" -H 'content-type: application/json' --data-binary "$(up_json "$1" "$2")" "http://$ADM/api/tls/upload"
}
tls_field() {
  curl -s -m 6 "${AUTH[@]}" "http://$ADM/api/tls" \
    | python3 -c "import sys,json;print(json.load(sys.stdin)['$1'])"
}

# A 组：先签一张已知域名的证书，后面断言才有确定的期望值
curl -s -m 6 "${AUTH[@]}" -X POST -H 'content-type: application/json' \
  -d '{"san":["upload.example.com"]}' "http://$ADM/api/tls/selfsigned" >/dev/null
check "证书概况带指纹（外部证书也能解析）" '"fingerprint"' "$(curl -s -m 6 "${AUTH[@]}" "http://$ADM/api/tls")"
cp "$(tls_field cert_path)" "$TMP/a-cert.pem"
cp "$(tls_field key_path)" "$TMP/a-key.pem"

# B 组：重签一次，手上就有一把与 A 证书对不上的私钥
curl -s -m 6 "${AUTH[@]}" -X POST -H 'content-type: application/json' \
  -d '{"san":["b.example.com"]}' "http://$ADM/api/tls/selfsigned" >/dev/null
UP_BAD="$(up_post "$TMP/a-cert.pem" "$(tls_field key_path)")"
check "证书与私钥对不上时拒绝上传" '"ok":false' "$UP_BAD"

UP_OK="$(up_post "$TMP/a-cert.pem" "$TMP/a-key.pem")"
check "合法证书对上传成功" '"ok":true' "$UP_OK"
check "上传回执带覆盖域名" 'upload.example.com' "$UP_OK"
check "上传回执带 SHA-256 指纹" '"fingerprint"' "$UP_OK"
check "上传后配置指向外部证书" '"self_signed":false' "$(curl -s -m 6 "${AUTH[@]}" "http://$ADM/api/tls")"
NEWKEY="$(printf '%s' "$UP_OK" | python3 -c 'import sys,json;print(json.load(sys.stdin)["key_path"])')"
check "私钥落盘 0600" '^600$' "$(stat -c %a "$NEWKEY" 2>/dev/null || echo unknown)"

echo "-- 自定义规则命中计入分析 --"
curl -s -o /dev/null -m 6 "http://$GW/rule-hit/one"
curl -s -o /dev/null -m 6 "http://$GW/rule-hit/two"
# 规则的命中记录在规则求值那一刻，与路由决策无关，所以单独一张表
RULE_RANK="$(curl -s -m 6 "${AUTH[@]}" "http://$ADM/api/stats?by=rule&range=3600&limit=20")"
check "自定义规则出现在 by=rule 排行榜" 'smoke-rule' "$RULE_RANK"
# grep 用 BRE，方括号要转义，否则会被当成字符类
check "规则维度可单独筛选" '"filter_fields":\["rule"\]' "$RULE_RANK"

echo "-- WebSocket / TOTP 二维码 / 采样间隔 --"
WS_CODE="$(curl -s -o /dev/null -w '%{http_code}' -m 2   -H 'Connection: Upgrade' -H 'Upgrade: websocket'   -H 'Sec-WebSocket-Version: 13' -H 'Sec-WebSocket-Key: x3JJHMbDL1EzLkh9GBhXDw=='   -b "$COOKIE" "http://$ADM/api/ws" 2>/dev/null || true)"
check "管理面 WebSocket 升级返回 101" '101' "$WS_CODE"
# 历史和排行榜不再走 HTTP 轮询：客户端在 WS 上声明视角，服务端按视角推
PROBE="$(python3 scripts/ws_probe.py "http://$ADM" "$COOKIE" 2>&1)"
check "WS 按视角推送历史/排行榜/配置" 'VIEW_OK' "$PROBE"
check "WS 的\"查看全部\"不被夹成 TOP1" 'ALL_OK' "$PROBE"
check "WS 承载写操作（命令 + 回执）" 'CMD_OK' "$PROBE"
check "应用状态走推送，不再单独轮询 /api/apps" 'APPS_OK' "$PROBE"
check "只读接口走 WS 查询通道（不再为翻页发 HTTP）" 'QUERY_OK' "$PROBE"
check "状态接口带进程占用" '"rss_bytes":' "$(curl -s -m 6 "${AUTH[@]}" "http://$ADM/api/status")"
check "进程占用带线程数" '"threads":' "$(curl -s -m 6 "${AUTH[@]}" "http://$ADM/api/status")"
check "TOTP 二维码返回 SVG" '<svg' "$(curl -s -m 6 "${AUTH[@]}" "http://$ADM/api/totp/qr?secret=JBSWY3DPEHPK3PXP&user=admin")"
check "二维码响应不缓存" 'no-store' "$(curl -si -m 6 "${AUTH[@]}" "http://$ADM/api/totp/qr?secret=JBSWY3DPEHPK3PXP" | tr -d '\r' | grep -i '^cache-control:')"

# 验证码校验：正解要过、错码要拒、算法不一致也要拒（这是"存完就登不进去"的防线）
TOTP_CODE="$(python3 -c "
import hmac,hashlib,base64,struct,time
k=base64.b32decode('JBSWY3DPEHPK3PXP')
d=hmac.new(k,struct.pack('>Q',int(time.time())//30),hashlib.sha1).digest()
o=d[-1]&15
print('%06d' % ((struct.unpack('>I',d[o:o+4])[0] & 0x7fffffff) % 1000000))
" 2>/dev/null)"
check "TOTP 校验接口接受正确码" '"ok":true' "$(curl -s -m 6 -X POST "${AUTH[@]}" -H 'content-type: application/json' \
  -d "{\"secret\":\"JBSWY3DPEHPK3PXP\",\"algorithm\":\"sha1\",\"code\":\"$TOTP_CODE\"}" "http://$ADM/api/totp/check")"
check "TOTP 校验接口拒绝错码" '"ok":false' "$(curl -s -m 6 -X POST "${AUTH[@]}" -H 'content-type: application/json' \
  -d '{"secret":"JBSWY3DPEHPK3PXP","algorithm":"sha1","code":"000000"}' "http://$ADM/api/totp/check")"
check "算法与 App 不一致时被拒" '"ok":false' "$(curl -s -m 6 -X POST "${AUTH[@]}" -H 'content-type: application/json' \
  -d "{\"secret\":\"JBSWY3DPEHPK3PXP\",\"algorithm\":\"sha256\",\"code\":\"$TOTP_CODE\"}" "http://$ADM/api/totp/check")"

patch_sample() {
  curl -s -m 6 "${AUTH[@]}" "http://$ADM/api/config" \
    | python3 -c "import sys,json; c=json.load(sys.stdin)['config']; c['metrics']['sample_interval_ms']=$1; print(json.dumps(c))" 2>/dev/null
}
SAMPLE_BODY="$(patch_sample 30000)"
check "PUT 采集间隔 30 秒" '"applied":true' "$(curl -s -m 6 -X PUT "${AUTH[@]}" -H 'content-type: application/json' -d "$SAMPLE_BODY" "http://$ADM/api/config")"
# 等热重载生效并在新间隔下补出第一个点（换间隔会清空历史）
for _ in $(seq 1 16); do
  if curl -s -m 3 "${AUTH[@]}" "http://$ADM/api/history?gran=60&range=3600" | grep -q '"points":\[{"t"'; then break; fi
  sleep 0.5
done
check "低于 5 秒的采集间隔被拒" '400' "$(code -X PUT "${AUTH[@]}" -H 'content-type: application/json' -d "$(patch_sample 1000)" "http://$ADM/api/config")"
check "超过 10 分钟的采集间隔被拒" '400' "$(code -X PUT "${AUTH[@]}" -H 'content-type: application/json' -d "$(patch_sample 9999999999)" "http://$ADM/api/config")"

# 粒度/范围是查询参数：不写配置，也就不会和别的会话打架
HIST="$(curl -s -m 6 "${AUTH[@]}" "http://$ADM/api/history?gran=60&range=3600")"
check "历史接口回显请求粒度（60s）" '"gran_secs":60' "$HIST"
check "历史接口按粒度返回桶宽" '"bucket_ms":60000' "$HIST"
check "历史接口回显请求范围（1h）" '"range_secs":3600' "$HIST"
check "点自带时间戳 t" '"t":' "$HIST"
# 范围比粒度还小的时候必须被夹到粒度，否则返回空图
check "范围小于粒度时自动夹到粒度" '"range_secs":60' "$(curl -s -m 6 "${AUTH[@]}" "http://$ADM/api/history?gran=60&range=1")"
# 粒度查询前后配置版本号不变 = 真的没有写配置
REV_BEFORE="$(curl -s -m 6 "${AUTH[@]}" "http://$ADM/api/config" | python3 -c 'import sys,json;print(json.load(sys.stdin)["rev"])' 2>/dev/null)"
curl -s -o /dev/null -m 6 "${AUTH[@]}" "http://$ADM/api/history?gran=3600&range=86400"
REV_AFTER="$(curl -s -m 6 "${AUTH[@]}" "http://$ADM/api/config" | python3 -c 'import sys,json;print(json.load(sys.stdin)["rev"])' 2>/dev/null)"
check "换粒度不写配置（版本号不变）" "$REV_BEFORE" "$REV_AFTER"

echo "-- 配置乐观锁 --"
CUR="$(curl -s -m 6 "${AUTH[@]}" "http://$ADM/api/config")"
REV="$(printf '%s' "$CUR" | python3 -c 'import sys,json;print(json.load(sys.stdin)["rev"])' 2>/dev/null)"
BODY="$(printf '%s' "$CUR" | python3 -c 'import sys,json;print(json.dumps(json.load(sys.stdin)["config"]))' 2>/dev/null)"
check "配置接口返回版本号" '^[0-9][0-9]*$' "$REV"
check "过期版本号写入被拒（409）" '409' "$(code -X PUT "${AUTH[@]}" -H 'content-type: application/json' -H 'x-optical-config-rev: 1' -d "$BODY" "http://$ADM/api/config")"
check "当前版本号写入成功" '"applied":true' "$(curl -s -m 6 -X PUT "${AUTH[@]}" -H 'content-type: application/json' -H "x-optical-config-rev: $REV" -d "$BODY" "http://$ADM/api/config")"

echo "-- 配置回溯 / 审计 --"
patch_timeout() {
  curl -s -m 6 "${AUTH[@]}" "http://$ADM/api/config" \
    | python3 -c "import sys,json; c=json.load(sys.stdin)['config']; c['server']['request_timeout_ms']=$1; print(json.dumps(c))" 2>/dev/null
}
read_timeout() {
  curl -s -m 6 "${AUTH[@]}" "http://$ADM/api/config" \
    | python3 -c 'import sys,json; print(json.load(sys.stdin)["config"]["server"]["request_timeout_ms"])' 2>/dev/null
}
check "PUT /api/config（9000）" '"applied":true' "$(curl -s -m 6 -X PUT "${AUTH[@]}" -H 'content-type: application/json' -d "$(patch_timeout 9000)" "http://$ADM/api/config")"
sleep 0.3
check "PUT /api/config（9500）" '"applied":true' "$(curl -s -m 6 -X PUT "${AUTH[@]}" -H 'content-type: application/json' -d "$(patch_timeout 9500)" "http://$ADM/api/config")"
check "当前生效值 9500" '9500' "$(read_timeout)"
SNAPS="$(curl -s -m 6 "${AUTH[@]}" "http://$ADM/api/snapshots")"
check "产生多份配置快照" '"reason"' "$SNAPS"
OLD_ID="$(printf '%s' "$SNAPS" | python3 -c 'import sys,json; s=json.load(sys.stdin)["snapshots"]; print(s[1]["id"] if len(s)>1 else "")' 2>/dev/null)"
check "取到旧快照 id" '\.toml' "$OLD_ID"
check "回溯快照成功" '"restored"' "$(curl -s -m 6 -X POST "${AUTH[@]}" "http://$ADM/api/snapshots/$OLD_ID/restore")"
sleep 0.3
check "回滚后配置恢复为 9000" '9000' "$(read_timeout)"
check "审计日志含 WAF 拦截" 'waf\.block' "$(curl -s -m 6 "${AUTH[@]}" "http://$ADM/api/audit")"

echo "-- 概述指标 --"
M="$(curl -s -m 6 "${AUTH[@]}" "http://$ADM/api/metrics")"
check "Top UA 有数据" '"ua":\[\[' "$M"
check "Top IP 有数据" '"ip":\[\[' "$M"
check "规则命中按族统计" 'family:' "$M"
check "状态码分布有数据" '"status":\[' "$M"

echo "-- 同一会话连续保存（热重载不能吃掉版本号）--"
REV_A="$(curl -s -m 6 "${AUTH[@]}" "http://$ADM/api/config" | python3 -c 'import sys,json;print(json.load(sys.stdin)["rev"])' 2>/dev/null)"
BODY_A="$(curl -s -m 6 "${AUTH[@]}" "http://$ADM/api/config" | python3 -c 'import sys,json;print(json.dumps(json.load(sys.stdin)["config"]))' 2>/dev/null)"
check "第一次保存" '"applied":true' "$(curl -s -m 6 -X PUT "${AUTH[@]}" -H 'content-type: application/json' -H "x-optical-config-rev: $REV_A" -d "$BODY_A" "http://$ADM/api/config")"
# 关键：保存完马上读一次版本号，然后等热重载跑过一轮（旧实现会在这里偷偷 +1）
REV_B="$(curl -s -m 6 "${AUTH[@]}" "http://$ADM/api/config" | python3 -c 'import sys,json;print(json.load(sys.stdin)["rev"])' 2>/dev/null)"
sleep 2
BODY_B="$(curl -s -m 6 "${AUTH[@]}" "http://$ADM/api/config" | python3 -c 'import sys,json;print(json.dumps(json.load(sys.stdin)["config"]))' 2>/dev/null)"
check "不刷新页面也能再次保存" '"applied":true' "$(curl -s -m 6 -X PUT "${AUTH[@]}" -H 'content-type: application/json' -H "x-optical-config-rev: $REV_B" -d "$BODY_B" "http://$ADM/api/config")"

echo "-- 自定义规则 --"
add_rules() {
  curl -s -m 6 "${AUTH[@]}" "http://$ADM/api/config" | python3 -c "
import sys, json
c = json.load(sys.stdin)['config']
c['rules'] = [
  {'name':'redir','enabled':True,'matches':[{'kind':'path','name':'','op':'prefix','value':'/r-redir'}],
   'actions':{'redirect':{'status':302,'to':'https://example.com{moved}'}}},
  {'name':'custom','enabled':True,'matches':[{'kind':'path','name':'','op':'prefix','value':'/r-custom'}],
   'actions':{'custom_response':{'status':200,'content_type':'text/plain','body':'RULE_OK'},'server_name':'rule-srv'}},
  {'name':'auth','enabled':True,'matches':[{'kind':'path','name':'','op':'prefix','value':'/r-auth'}],
   'actions':{'token_auth':{'name':'x-token','value':'s3cret','from_query':False}}},
  {'name':'fail','enabled':False,'matches':[{'kind':'host','name':'','op':'eq','value':'nope'}],'actions':{}}
]
print(json.dumps(c))
" 2>/dev/null
}
RREV="$(curl -s -m 6 "${AUTH[@]}" "http://$ADM/api/config" | python3 -c 'import sys,json;print(json.load(sys.stdin)["rev"])' 2>/dev/null)"
check "写入自定义规则" '"applied":true' "$(curl -s -m 6 -X PUT "${AUTH[@]}" -H 'content-type: application/json' -H "x-optical-config-rev: $RREV" -d "$(add_rules)" "http://$ADM/api/config")"
sleep 1.5
REDIR_HEAD="$(curl -si -m 6 "http://$GW/r-redir/x" | tr -d '\r' | head -12)"
check "规则重定向返回 302" '302' "$(printf '%s' "$REDIR_HEAD" | head -1)"
check "重定向 Location 正确" 'example.com' "$(printf '%s' "$REDIR_HEAD" | grep -i '^location:')"
check "自定义返回页面" 'RULE_OK' "$(curl -s -m 6 "http://$GW/r-custom/")"
check "自定义 server 名" 'rule-srv' "$(curl -si -m 6 "http://$GW/r-custom/" | tr -d '\r' | grep -i '^server:')"
check "规则命中标记" 'custom' "$(curl -si -m 6 "http://$GW/r-custom/" | tr -d '\r' | grep -i '^x-optical-rule:')"
check "Token 鉴权拦截无令牌请求" '401' "$(code "http://$GW/r-auth/")"
check "Token 鉴权放行正确令牌" '200' "$(code -H 'x-token: s3cret' "http://$GW/r-auth/")"

echo "-- 规则级限速 / ALL 匹配 --"
# ALL 条件 + 全程共享的令牌桶（key=rule），这样断言不受来源 IP 影响。
# 测完必须立刻把规则摘掉，不然后面所有用例都会撞 429。
add_limit_rule() {
  curl -s -m 6 "${AUTH[@]}" "http://$ADM/api/config" | python3 -c "
import sys, json
c = json.load(sys.stdin)['config']
c.setdefault('rules', []).append({
  'name': 'smoke-limit', 'enabled': True,
  'matches': [{'kind': 'all', 'name': '', 'op': 'eq', 'value': ''}],
  'actions': {'rate_limit': {'qps': 1, 'burst': 1, 'key': 'rule', 'status_code': 429}},
})
print(json.dumps(c))
" 2>/dev/null
}
LREV="$(curl -s -m 6 "${AUTH[@]}" "http://$ADM/api/config" | python3 -c 'import sys,json;print(json.load(sys.stdin)["rev"])' 2>/dev/null)"
check "写入 ALL 限速规则" '"applied":true' \
  "$(curl -s -m 6 -X PUT "${AUTH[@]}" -H 'content-type: application/json' \
     -H "x-optical-config-rev: $LREV" -d "$(add_limit_rule)" "http://$ADM/api/config")"
sleep 1.5
# burst=1：第一个放行，紧接着的第二个必须被限
FIRST="$(code "http://$GW/hello")"
SECOND="$(code "http://$GW/hello")"
check "ALL 规则下的第一个请求放行" '200' "$FIRST"
check "超过 QPS 被限速（429）" '429' "$SECOND"
check "限速响应带 Retry-After" 'retry-after' \
  "$(curl -si -m 6 "http://$GW/hello" | tr -d '\r' | tr 'A-Z' 'a-z' | grep -o '^retry-after')"

# 摘掉限速规则：不能留给后面的用例
LREV2="$(curl -s -m 6 "${AUTH[@]}" "http://$ADM/api/config" | python3 -c 'import sys,json;print(json.load(sys.stdin)["rev"])' 2>/dev/null)"
BODY_CLEAN="$(curl -s -m 6 "${AUTH[@]}" "http://$ADM/api/config" | python3 -c '
import sys, json
c = json.load(sys.stdin)["config"]
c["rules"] = [r for r in c.get("rules", []) if r.get("name") != "smoke-limit"]
print(json.dumps(c))
' 2>/dev/null)"
curl -s -m 8 -X PUT "${AUTH[@]}" -H 'content-type: application/json' \
  -H "x-optical-config-rev: $LREV2" --data-binary "$BODY_CLEAN" "http://$ADM/api/config" >/dev/null
sleep 1.2
check "移除限速规则后恢复正常" '200' "$(code "http://$GW/hello")"

echo "-- 排行榜（维度 / 范围 / 筛选） --"
STATS="$(curl -s -m 6 "${AUTH[@]}" "http://$ADM/api/stats?by=route&range=3600")"
check "按路由出排行榜" '"by":"route"' "$STATS"
check "排行榜带请求数" '"requests":' "$STATS"
check "limit 超过防呆上限时被夹住" '"limit":5000' "$(curl -s -m 6 "${AUTH[@]}" "http://$ADM/api/stats?by=ip&range=3600&limit=999999")"
# limit=0 才是"查看全部"：服务端不截断，并且给回真实总量与返回行数
ALL="$(curl -s -m 6 "${AUTH[@]}" "http://$ADM/api/stats?by=ip&range=3600&limit=0")"
check "limit=0 表示查看全部" '"limit":0' "$ALL"
check "返回行数如实给出" '"returned":' "$ALL"
check "真实总量单独给出" '"total":' "$ALL"
check "长尾裁剪标记如实给出" '"trimmed":' "$ALL"
check "能按后端分组" '"by":"backend"' "$(curl -s -m 6 "${AUTH[@]}" "http://$ADM/api/stats?by=backend&range=3600")"
check "组合维度可互相筛选" '"filter_fields":\["route","backend","host","status"\]' "$STATS"
# 跨维度筛选：按路由看，只要 2xx —— 结果里不能出现非 2xx 的错误
check "状态码 2xx 筛选生效" '"key":"api"' "$(curl -s -m 6 "${AUTH[@]}" "http://$ADM/api/stats?by=route&range=3600&f=status:eq:2xx")"
# IP 表没有路由信息，这种筛选必须如实报告"用不上"，不能悄悄当成没写
check "不适用的筛选被如实报告" '"dropped_filters":\["route"\]' "$(curl -s -m 6 "${AUTH[@]}" "http://$ADM/api/stats?by=ip&range=3600&f=route:eq:api")"
# 排行榜不能改配置（和时间范围/粒度一样，都是纯查询）
REV_S1="$(curl -s -m 6 "${AUTH[@]}" "http://$ADM/api/config" | python3 -c 'import sys,json;print(json.load(sys.stdin)["rev"])' 2>/dev/null)"
curl -s -o /dev/null -m 6 "${AUTH[@]}" "http://$ADM/api/stats?by=status&range=86400&f=route:contains:a"
REV_S2="$(curl -s -m 6 "${AUTH[@]}" "http://$ADM/api/config" | python3 -c 'import sys,json;print(json.load(sys.stdin)["rev"])' 2>/dev/null)"
check "查排行榜不写配置（版本号不变）" "$REV_S1" "$REV_S2"

# WAF 维度：内置检测项必须能单独看、单独筛，而不是混进「自定义规则」
WAFRANK="$(curl -s -m 6 "${AUTH[@]}" "http://$ADM/api/stats?by=waf&range=3600&limit=10")"
check "WAF 维度能列出被拦的检测项" '"by":"waf"' "$WAFRANK"
check "WAF 维度有数据（前面刚拦过 SQL 注入）" 'sql' "$WAFRANK"
# grep 用 BRE，方括号必须转义，否则会被当成字符类
check "WAF 维度可单独筛选" '"filter_fields":\["waf"\]' "$WAFRANK"
check "WAF 项不会漏进自定义规则维度" 'yes' "$(\
  curl -s -m 6 "${AUTH[@]}" "http://$ADM/api/stats?by=rule&range=3600&limit=20" | python3 -c '
import sys, json
rows = json.load(sys.stdin).get("rows") or []
keys = [r.get("key", "") for r in rows]
print("no" if any(k.startswith(("sql-", "xss-", "path-")) for k in keys) else "yes")
')"

# 大范围：前端能选 30 天，后端就不能把请求夹成 7 天
H30="$(curl -s -m 6 "${AUTH[@]}" "http://$ADM/api/history?gran=3600&range=2592000")"
check "30 天范围不再被夹短" '"range_secs":2592000' "$H30"
check "历史带长期留存天数" '"history_days":90' "$H30"
check "历史带长期环桶宽" '"coarse_bucket_ms":3600000' "$H30"

echo "-- CLI status（本地令牌） --"
ST="$("$BIN" --config "$CFG" status)"
check "status 通过本地令牌认证" '运行中' "$ST"
check "status 显示 WAF 状态" 'WAF' "$ST"
check "status 显示缓存命中率" '命中率' "$ST"

echo "-- 规则关系判断（纯逻辑，不起服务） --"
if command -v node >/dev/null 2>&1; then
  REL="$(node "$(dirname "$0")/rel_test.js" 2>&1)"
  check "关系判断：重叠/完全重复/受影响目标" '关系判断全部通过' "$REL"
else
  echo "  SKIP 未安装 node，跳过关系判断"
fi

echo "-- IP 黑白名单 --"
# 用「白名单模式」测闸门：只放行 127.0.0.1，其它全拒。
# 这样既验证了 deny 真的在拦，又不会把本机冒烟流量一起打死。
curl -s -m 6 "${AUTH[@]}" -X POST -H 'content-type: application/json' \
  -d '{"text":"allow 127.0.0.1/32\ndeny 0.0.0.0/0\ndeny 2001:db8::/32","mode":"replace"}' \
  "http://$ADM/api/ipfilter/import" >/dev/null
IPF="$(curl -s -m 6 "${AUTH[@]}" "http://$ADM/api/ipfilter")"
check "名单导入后有 3 条" '"cidr":"2001:db8::/32"' "$IPF"
check "IPv6 网段也能导入" '2001:db8::/32' "$IPF"

# 打开白名单模式
CFGJSON="$(curl -s -m 6 "${AUTH[@]}" "http://$ADM/api/config")"
REV="$(printf '%s' "$CFGJSON" | python3 -c 'import sys,json;print(json.load(sys.stdin)["rev"])')"
BODY="$(printf '%s' "$CFGJSON" | python3 -c '
import sys, json
d = json.load(sys.stdin)["config"]
f = d.setdefault("ip_filter", {})
f["enabled"] = True
f["default_action"] = "deny"
f["status_code"] = 403
print(json.dumps(d))
')"
curl -s -m 8 "${AUTH[@]}" -X PUT -H 'content-type: application/json' \
  -H "x-optical-config-rev: $REV" --data-binary "$BODY" "http://$ADM/api/config" >/dev/null

check "白名单里的地址照常通过" '200' "$(code "http://$GW/hello")"
check "白名单外的地址被拒" 'deny' "$(curl -s -m 6 "${AUTH[@]}" -X POST -H 'content-type: application/json' -d '{"ip":"8.8.8.8"}' "http://$ADM/api/ipfilter/check")"
check "命中规则能报出来" '"rule":"0.0.0.0/0"' "$(curl -s -m 6 "${AUTH[@]}" -X POST -H 'content-type: application/json' -d '{"ip":"8.8.8.8"}' "http://$ADM/api/ipfilter/check")"
check "先命中先算（allow 压住后面的 deny）" '"action":"allow"' "$(curl -s -m 6 "${AUTH[@]}" -X POST -H 'content-type: application/json' -d '{"ip":"127.0.0.1"}' "http://$ADM/api/ipfilter/check")"
check "IPv6 命中独立网段" '"rule":"2001:db8::/32"' "$(curl -s -m 6 "${AUTH[@]}" -X POST -H 'content-type: application/json' -d '{"ip":"2001:db8::5"}' "http://$ADM/api/ipfilter/check")"

# 导出格式与导入对称，能原样贴回去
EXP="$(curl -s -m 6 "${AUTH[@]}" "http://$ADM/api/ipfilter/export")"
check "导出包含 allow 行" 'allow 127.0.0.1/32' "$EXP"
check "导出包含 IPv6 行" 'deny 2001:db8::/32' "$EXP"

# 关掉，别影响后面的用例
IDX="$(curl -s -m 6 "${AUTH[@]}" "http://$ADM/api/ipfilter")"
REV2="$(curl -s -m 6 "${AUTH[@]}" "http://$ADM/api/config" | python3 -c 'import sys,json;print(json.load(sys.stdin)["rev"])')"
BODY2="$(curl -s -m 6 "${AUTH[@]}" "http://$ADM/api/config" | python3 -c '
import sys, json
d = json.load(sys.stdin)["config"]
d.setdefault("ip_filter", {})["enabled"] = False
print(json.dumps(d))
')"
curl -s -m 8 "${AUTH[@]}" -X PUT -H 'content-type: application/json' \
  -H "x-optical-config-rev: $REV2" --data-binary "$BODY2" "http://$ADM/api/config" >/dev/null

echo "-- 外观（主题色 / 图片上传）--"
# 1x1 透明 PNG：只验证链路，不关心好不好看
PNG1="iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=="
check "外观接口不登录也能读（登录页要用）" '"ok":true' "$(curl -s -m 6 "http://$ADM/api/appearance")"

UP="$(curl -s -m 8 "${AUTH[@]}" -H 'content-type: application/json' \
  -d "{\"kind\":\"rail\",\"data\":\"data:image/png;base64,$PNG1\"}" \
  "http://$ADM/api/appearance/upload")"
check "图标上传成功" '"kind":"rail"' "$UP"
check "返回的地址带版本号（换图即换缓存键）" '/api/branding/rail?v=' "$UP"
check "图片落到 data_dir/branding" 'rail.png' "$(ls "$TMP/data/branding" 2>/dev/null)"
check "品牌图公开可取" '200' "$(code "http://$ADM/api/branding/rail")"
check "品牌图禁止嗅探（防把坏文件当脚本执行）" 'nosniff' \
  "$(curl -s -D - -o /dev/null -m 6 "http://$ADM/api/branding/rail" | tr -d '\r')"

# 谎报 mime 必须被拒：魔数说了才算
BADUP="$(curl -s -m 8 "${AUTH[@]}" -H 'content-type: application/json' \
  -d '{"kind":"rail","data":"data:image/png;base64,aGVsbG8="}' \
  "http://$ADM/api/appearance/upload")"
check "内容不是图片就拒绝" '"ok":false' "$BADUP"
check "不认识的图片位被拒绝" '"ok":false' \
  "$(curl -s -m 8 "${AUTH[@]}" -H 'content-type: application/json' -d "{\"kind\":\"favicon\",\"data\":\"data:image/png;base64,$PNG1\"}" "http://$ADM/api/appearance/upload")"

# 主题色：保存后读回，非法值要回落而不是原样存下来
curl -s -m 6 "${AUTH[@]}" -X PUT -H 'content-type: application/json' \
  -d '{"enabled":true,"accent":"#7C5CFF","chart_style":"bar"}' "http://$ADM/api/appearance" >/dev/null
AP="$(curl -s -m 6 "http://$ADM/api/appearance")"
check "主题色保存并按小写读回" '"accent":"#7c5cff"' "$AP"
check "图表样式保存为柱状" '"chart_style":"bar"' "$AP"
check "上传的图标出现在外观数据里" '/api/branding/rail?v=' "$AP"

curl -s -m 6 "${AUTH[@]}" -X PUT -H 'content-type: application/json' \
  -d '{"accent":"red","chart_style":"pie"}' "http://$ADM/api/appearance" >/dev/null
AP2="$(curl -s -m 6 "http://$ADM/api/appearance")"
check "非法主题色回落到默认蓝" '"accent":"#0052d9"' "$AP2"
check "非法图表样式回落到折线" '"chart_style":"line"' "$AP2"

# 面板不透明度：能存能读，低于可读下限要被夹住（不是原样存下来）
curl -s -m 6 "${AUTH[@]}" -X PUT -H 'content-type: application/json' \
  -d '{"panel_alpha":72}' "http://$ADM/api/appearance" >/dev/null
check "面板不透明度能保存" '"panel_alpha":72' "$(curl -s -m 6 "http://$ADM/api/appearance")"
curl -s -m 6 "${AUTH[@]}" -X PUT -H 'content-type: application/json' \
  -d '{"panel_alpha":5}' "http://$ADM/api/appearance" >/dev/null
check "过低的透明度被夹到 55" '"panel_alpha":55' "$(curl -s -m 6 "http://$ADM/api/appearance")"

check "移除图标" '"removed":true' \
  "$(curl -s -m 6 "${AUTH[@]}" -X DELETE "http://$ADM/api/appearance/asset/rail")"
check "移除后回到内置" '"rail":""' "$(curl -s -m 6 "http://$ADM/api/appearance")"

# 收尾：关掉自定义外观，别影响后续用例的视觉断言
curl -s -m 6 "${AUTH[@]}" -X PUT -H 'content-type: application/json' \
  -d '{"enabled":false}' "http://$ADM/api/appearance" >/dev/null

echo "-- 维护与清理 --"
# 不依赖前面用例留下的会话：它们可能改过安全设置、也可能顶掉过会话。
# 清理类接口必须能在一个"刚登录"的干净会话上工作。
curl -s -m 6 -D "$TMP/mhdr.txt" -X POST "http://$ADM/api/auth/login" \
  -H 'content-type: application/json' -d "{\"username\":\"admin\",\"password\":\"$PASSWD\"}" >/dev/null
COOKIE="$(grep -i '^set-cookie:' "$TMP/mhdr.txt" | sed 's/^[Ss]et-[Cc]ookie: //' | cut -d';' -f1 | tr -d '\r')"
AUTH=(-H "cookie: $COOKIE")
MT="$(curl -s -m 6 "${AUTH[@]}" "http://$ADM/api/maintenance")"
check "维护接口给出缓存状态" '"entries"' "$MT"
check "维护接口给出在途请求数" '"in_flight"' "$MT"
check "维护接口给出限速桶数量" '"rate_buckets"' "$MT"
check "维护接口给出水位阈值" '"high_water_bytes"' "$MT"
check "手动清空代理缓存" '"ok":true' \
  "$(curl -s -m 6 -X POST "${AUTH[@]}" -H 'content-type: application/json' -d '{"cache":true}' "http://$ADM/api/maintenance/purge")"
check "手动清空排行榜统计" '"ok":true' \
  "$(curl -s -m 6 -X POST "${AUTH[@]}" -H 'content-type: application/json' -d '{"stats":true}' "http://$ADM/api/maintenance/purge")"
check "空选择被拒绝（避免误触成全清）" '"ok":false' \
  "$(curl -s -m 6 -X POST "${AUTH[@]}" -H 'content-type: application/json' -d '{}' "http://$ADM/api/maintenance/purge")"
check "清空后缓存条目归零" '"entries":0' "$(curl -s -m 6 "${AUTH[@]}" "http://$ADM/api/maintenance")"

echo "-- 背压配置 --"
BP="$(curl -s -m 6 "${AUTH[@]}" "http://$ADM/api/config")"
check "背压字段出现在配置里" '"max_in_flight"' "$BP"
check "维护字段出现在配置里" '"cache_high_pct"' "$BP"

echo "-- 登录设备 / 单点登录 --"
CJ1="$TMP/c1.txt"
CJ2="$TMP/c2.txt"
login_as() {  # login_as <cookie-jar> <ua>
  curl -s -c "$1" -A "$2" -m 6 -H 'content-type: application/json' \
    -d "{\"username\":\"admin\",\"password\":\"$PASSWD\"}" "http://$ADM/api/auth/login" >/dev/null
}
login_as "$CJ1" 'Mozilla/5.0 (Windows NT 10.0) AppleWebKit Chrome/120 Safari/537.36'
login_as "$CJ2" 'Mozilla/5.0 (Macintosh; Intel Mac OS X) Firefox/121'
SESS="$(curl -s -b "$CJ1" -m 6 "http://$ADM/api/sessions")"
check "会话列表认得出客户端" 'Chrome · Windows' "$SESS"
check "会话列表带来源地址" '127.0.0.1' "$SESS"
check "能标出当前会话" '"current":true' "$SESS"
check "只给短 id，不泄露令牌" '"id":"[0-9a-f]\{12\}"' "$SESS"
# 不能断言"正好 2 条"：脚本自己的会话也在列表里，数量随前面的用例浮动。
# 要断言的是"这两条确实都在"。
check "两条会话都在" 'yes' "$(printf '%s' "$SESS" | python3 -c '
import sys, json
rows = json.load(sys.stdin)["sessions"]
uas = [r["ua"] for r in rows]
print("yes" if "Chrome · Windows" in uas and "Firefox · macOS" in uas and len(rows) >= 2 else "no")
')"

OTHER="$(printf '%s' "$SESS" | python3 -c 'import sys,json
d=json.load(sys.stdin)
print(next(s["id"] for s in d["sessions"] if not s["current"]))')"
check "按 id 下线指定设备" '"removed":true' \
  "$(curl -s -b "$CJ1" -m 6 -X DELETE "http://$ADM/api/sessions/$OTHER")"
check "被踢掉的会话立刻失效" '401' "$(code -b "$CJ2" "http://$ADM/api/status")"

# 单点登录：新登录必须顶掉旧会话。这一步会清掉本脚本自己的会话，
# 所以放在最后，跑完再重新登录一次收尾。
login_as "$CJ2" 'curl/8.0'
CFGJ="$(curl -s -b "$CJ1" -m 6 "http://$ADM/api/config")"
REV3="$(printf '%s' "$CFGJ" | python3 -c 'import sys,json;print(json.load(sys.stdin)["rev"])')"
BODY3="$(printf '%s' "$CFGJ" | python3 -c '
import sys, json
d = json.load(sys.stdin)["config"]
d["admin"]["session_ttl_secs"] = d["admin"].get("session_ttl_secs", 3600)
d["admin"]["single_session"] = True
print(json.dumps(d))
')"
curl -s -b "$CJ1" -m 8 -X PUT -H 'content-type: application/json' \
  -H "x-optical-config-rev: $REV3" --data-binary "$BODY3" "http://$ADM/api/config" >/dev/null
check "单点登录开关写进配置" '"single_session":true' \
  "$(curl -s -b "$CJ1" -m 6 "http://$ADM/api/config")"

login_as "$CJ2" 'Mozilla/5.0 (X11; Linux) Chrome/121'
check "新登录顶掉旧会话（单点登录生效）" '401' "$(code -b "$CJ1" "http://$ADM/api/status")"
check "新会话本身可用" '200' "$(code -b "$CJ2" "http://$ADM/api/status")"
check "只剩一条会话" '1' \
  "$(curl -s -b "$CJ2" -m 6 "http://$ADM/api/sessions" | python3 -c 'import sys,json;print(len(json.load(sys.stdin)["sessions"]))')"

# 关掉单点登录，别把演示机留在"开一个浏览器就顶掉另一个"的状态
CFGJ2="$(curl -s -b "$CJ2" -m 6 "http://$ADM/api/config")"
REV4="$(printf '%s' "$CFGJ2" | python3 -c 'import sys,json;print(json.load(sys.stdin)["rev"])')"
BODY4="$(printf '%s' "$CFGJ2" | python3 -c '
import sys, json
d = json.load(sys.stdin)["config"]
d["admin"]["single_session"] = False
print(json.dumps(d))
')"
curl -s -b "$CJ2" -m 8 -X PUT -H 'content-type: application/json' \
  -H "x-optical-config-rev: $REV4" --data-binary "$BODY4" "http://$ADM/api/config" >/dev/null
check "单点登录可关回去" '"single_session":false' \
  "$(curl -s -b "$CJ2" -m 6 "http://$ADM/api/config")"



echo
if [ "$FAIL" -eq 0 ]; then
  printf '\033[32m全部通过：%d 项\033[0m\n' "$PASS"
  exit 0
else
  printf '\033[31m失败 %d 项 / 通过 %d 项\033[0m\n' "$FAIL" "$PASS"
  echo "--- gateway log (tail) ---"
  tail -n 30 "$TMP/gw.log"
  exit 1
fi
