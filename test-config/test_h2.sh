#!/bin/bash
# CaddyGuard HTTP/2 组合规则测试（真实 TLS + h2，端口 19443）
# 证书来自 corefusion 目录（tycng.com），测试机执行。

set +e

CADDY="/opt/caddyguard/caddy"
CONF_DIR="/opt/caddyguard/test-config"
RULE_DIR="/opt/caddyguard/rule-config"
TARGET="https://tycng.com:19443"
CURL="curl -k -s -o /dev/null -m 20 --resolve tycng.com:19443:127.0.0.1"
CONFIG_BAK="/tmp/config.h2test.$$"
PASS=0
FAIL=0

cleanup() {
    cp "$CONFIG_BAK" "$RULE_DIR/config.json" 2>/dev/null || true
    local pids=$(ss -tlnp 2>/dev/null | grep -E ':19443 |:8889 ' | grep -oP 'pid=\K[0-9]+' | sort -u)
    [ -n "$pids" ] && echo "$pids" | xargs kill 2>/dev/null
    rm -f "$CONFIG_BAK"
}
trap cleanup EXIT INT TERM

test_rule() {
    local name="$1" expect="$2"
    shift 2
    local actual=$($CURL -w "%{http_code}" "$@")
    if [ "$actual" = "$expect" ]; then
        printf "  PASS  %-48s (%s)\n" "$name" "$actual"
        PASS=$((PASS+1))
    else
        printf "  FAIL  %-48s (got %s, want %s)\n" "$name" "$actual" "$expect"
        FAIL=$((FAIL+1))
    fi
}

echo "========================================"
echo "  CaddyGuard HTTP/2 规则测试"
echo "  $(date '+%Y-%m-%d %H:%M:%S')"
echo "========================================"

cp "$RULE_DIR/config.json" "$CONFIG_BAK"
cat > "$RULE_DIR/config.json" <<'EOF'
{"waf_enable":"on","trust_proxy_headers":"on","log_dir":"/tmp","white_url_check":"on","white_ip_check":"on","white_ua_check":"on","black_ip_check":"on","url_check":"on","url_args_check":"on","user_agent_check":"on","header_check":"on","cookie_check":"on","referer_check":"off","file_upload_check":"on","cc_check":"off","cc_rate":"999999/60","cc_mode":"ip","cc_block_ttl":0,"post_check":"on","bodyless":"on","multipart_streaming_check":"off","upload_filename_scan_limit":0,"post_body_scan_limit":2097152,"match_cache":"on","score_block_threshold":0,"waf_output":"html","waf_redirect_url":""}
EOF
rm -f /tmp/$(date +%F)_waf.log

# 后端
if [ "$(curl -s -m 2 -o /dev/null -w '%{http_code}' http://127.0.0.1:8889/)" != "200" ]; then
    nohup "$CADDY" run --config "$CONF_DIR/Caddyfile.backend" --adapter caddyfile > /tmp/cg_h2_backend.log 2>&1 &
    sleep 1
fi
nohup "$CADDY" run --config "$CONF_DIR/Caddyfile.h2test" --adapter caddyguardfile > /tmp/cg_h2_waf.log 2>&1 &
sleep 3

test_rule "h2 baseline" 200 --http2 -A "Mozilla/5.0" "$TARGET/"
test_rule "h2 90 headers + content-type" 403 --http2 -A "Mozilla/5.0" -H "Content-Type: text/plain" $(for i in $(seq 1 90); do printf ' -H X-T%d:v%d' $i $i; done) "$TARGET/combo-h2-test"
test_rule "h1.1 90 headers + content-type" 200 --http1.1 -A "Mozilla/5.0" -H "Content-Type: text/plain" $(for i in $(seq 1 90); do printf ' -H X-T%d:v%d' $i $i; done) "$TARGET/combo-h2-test"
test_rule "h2 90 headers + CL:0" 200 --http2 -A "Mozilla/5.0" -H "Content-Type: text/plain" -H "Content-Length: 0" $(for i in $(seq 1 90); do printf ' -H X-T%d:v%d' $i $i; done) "$TARGET/combo-h2-test"
test_rule "h2 90 headers no content-type" 200 --http2 -A "Mozilla/5.0" $(for i in $(seq 1 90); do printf ' -H X-T%d:v%d' $i $i; done) "$TARGET/combo-h2-test"
test_rule "h2 10 headers + content-type" 200 --http2 -A "Mozilla/5.0" -H "Content-Type: text/plain" $(for i in $(seq 1 10); do printf ' -H X-T%d:v%d' $i $i; done) "$TARGET/combo-h2-test"

if grep -q 'CVE-2026-119618 mod_http2 header flood' /tmp/$(date +%F)_waf.log 2>/dev/null; then
    echo "  PASS  Combo_BLOCK CVE-2026-119618 logged"
    PASS=$((PASS+1))
else
    echo "  FAIL  Combo_BLOCK CVE-2026-119618 log missing"
    FAIL=$((FAIL+1))
fi

echo ""
echo "========================================"
echo "  PASS: $PASS  FAIL: $FAIL"
echo "========================================"
[ "$FAIL" -eq 0 ]
