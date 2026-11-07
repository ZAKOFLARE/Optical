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

echo "-- WebSocket / TOTP 二维码 / 采样间隔 --"
WS_CODE="$(curl -s -o /dev/null -w '%{http_code}' -m 2   -H 'Connection: Upgrade' -H 'Upgrade: websocket'   -H 'Sec-WebSocket-Version: 13' -H 'Sec-WebSocket-Key: x3JJHMbDL1EzLkh9GBhXDw=='   -b "$COOKIE" "http://$ADM/api/ws" 2>/dev/null || true)"
check "管理面 WebSocket 升级返回 101" '101' "$WS_CODE"
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

echo "-- CLI status（本地令牌） --"
ST="$("$BIN" --config "$CFG" status)"
check "status 通过本地令牌认证" '运行中' "$ST"
check "status 显示 WAF 状态" 'WAF' "$ST"
check "status 显示缓存命中率" '命中率' "$ST"

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
