#!/bin/bash
# CaddyGuard 三层组合规则测试（隔离 :8888/:8889）
# 注意：脚本会 kill 名为 caddy 的进程，只能在测试机执行，勿在生产机直接跑。
# 测试目标：192.168.2.180（或本机隔离环境）

set +e

CADDY="/opt/caddyguard/caddy"
CONF_DIR="/opt/caddyguard/test-config"
RULE_DIR="/opt/caddyguard/rule-config"
TARGET="http://127.0.0.1:8888"
PASS=0
FAIL=0
ERRORS=""
COMBO_BAK="/tmp/combo.combo_test.$$"
CONFIG_BAK="/tmp/config.combo_test.$$"

cleanup() {
    cp "$COMBO_BAK" "$RULE_DIR/combo.jsonl" 2>/dev/null || true
    cp "$CONFIG_BAK" "$RULE_DIR/config.json" 2>/dev/null || true
    kill $(pgrep -x caddy) 2>/dev/null || true
    rm -f "$COMBO_BAK" "$CONFIG_BAK" /tmp/cg_j1.json /tmp/cg_j25.json /tmp/cg_photo15.jpg /tmp/cg_photo5.jpg
}
trap cleanup EXIT INT TERM

test_rule() {
    local name="$1" expect="$2"
    shift 2
    local actual=$(curl -s -o /dev/null -m 60 -w "%{http_code}" "$@" 2>/dev/null)
    if [ "$actual" = "$expect" ]; then
        printf "  PASS  %-48s (HTTP %s)\n" "$name" "$actual"
        PASS=$((PASS+1))
    else
        printf "  FAIL  %-48s (got %s, want %s)\n" "$name" "$actual" "$expect"
        FAIL=$((FAIL+1))
        ERRORS="$ERRORS\n  $name: got $actual, want $expect"
    fi
}

log_has() {
    grep -q "$1" /tmp/$(date +%F)_waf.log 2>/dev/null
}

echo "========================================"
echo "  CaddyGuard 三层组合规则测试"
echo "  $(date '+%Y-%m-%d %H:%M:%S')"
echo "========================================"

kill $(pgrep -x caddy) 2>/dev/null || true
sleep 1
rm -f /tmp/$(date +%F)_waf.log
cp "$RULE_DIR/combo.jsonl" "$COMBO_BAK"
cp "$RULE_DIR/config.json" "$CONFIG_BAK"

cat > "$RULE_DIR/config.json" <<'EOF'
{"waf_enable":"on","trust_proxy_headers":"on","log_dir":"/tmp","white_url_check":"on","white_ip_check":"on","white_ua_check":"on","black_ip_check":"on","url_check":"on","url_args_check":"on","user_agent_check":"on","header_check":"on","cookie_check":"on","referer_check":"off","file_upload_check":"on","cc_check":"off","cc_rate":"999999/60","cc_mode":"ip","cc_block_ttl":0,"post_check":"on","bodyless":"on","multipart_streaming_check":"off","upload_filename_scan_limit":0,"post_body_scan_limit":2097152,"match_cache":"on","score_block_threshold":0,"waf_output":"html","waf_redirect_url":""}
EOF

nohup "$CADDY" run --config "$CONF_DIR/Caddyfile.backend" --adapter caddyfile > /tmp/cg_backend.log 2>&1 &
sleep 1
nohup "$CADDY" run --config "$CONF_DIR/Caddyfile.test" --adapter caddyguardfile > /tmp/cg_waf.log 2>&1 &
sleep 3

test_rule "baseline" 200 -A "Mozilla/5.0" "$TARGET/"
test_rule "WP setup-config" 403 -A "Mozilla/5.0" "$TARGET/wp-admin/setup-config.php"
test_rule "WP setup-config uppercase" 403 -A "Mozilla/5.0" "$TARGET/WP-ADMIN/SETUP-CONFIG.PHP"
test_rule "WP upgrade php" 403 -A "Mozilla/5.0" "$TARGET/wp-content/upgrade/evil.php"
test_rule "WP upgrade txt control" 200 -A "Mozilla/5.0" "$TARGET/wp-content/upgrade/evil.txt"
test_rule "Axis SOAP Fault" 403 -A "Mozilla/5.0" -H "Content-Type: text/xml" --data '<?xml version="1.0"?><soap:Fault><soap:exceptionName>x</soap:exceptionName></soap:Fault>' "$TARGET/"
test_rule "phpAfterShell upload field" 403 -A "Mozilla/5.0" -F "PHP_SESSION_UPLOAD_PROGRESS=abc" "$TARGET/"
test_rule "legacy sqlmap UA" 403 -A "sqlmap/1.7" "$TARGET/"

python3 - <<'PY'
open('/tmp/cg_j1.json','wb').write(b'{"a":"'+b'x'*1000000+b'"}')
open('/tmp/cg_j25.json','wb').write(b'{"a":"'+b'x'*2500000+b'"}')
PY
head -c 1500000 /dev/urandom > /tmp/cg_photo15.jpg
head -c 5242880 /dev/urandom > /tmp/cg_photo5.jpg
test_rule "1MB JSON" 200 -A "Mozilla/5.0" -H "Content-Type: application/json" --data-binary @/tmp/cg_j1.json "$TARGET/"
test_rule "2.5MB JSON" 403 -A "Mozilla/5.0" -H "Content-Type: application/json" --data-binary @/tmp/cg_j25.json "$TARGET/"
test_rule "1.5MB multipart jpg" 200 -A "Mozilla/5.0" -F "file=@/tmp/cg_photo15.jpg" "$TARGET/"
test_rule "5MB multipart jpg" 403 -A "Mozilla/5.0" -F "file=@/tmp/cg_photo5.jpg" "$TARGET/"

# 热加载：LOG / SCORE / 坏正则 / 大小写
cat >> "$RULE_DIR/combo.jsonl" <<'EOF'
{"id":"tmp-url-log","if":"url","action":"LOG"}
{"id":"tmp-score-a","if":{"cond":"uri","op":"prefix","value":"/scoretest"},"action":"SCORE","score":10}
{"id":"tmp-score-b","if":{"cond":"uri","op":"prefix","value":"/scoretest"},"action":"SCORE","score":10}
{"id":"tmp-ci-re","if":["AND",{"cond":"uri","op":"prefix","value":"/CITEST"},{"cond":"args","op":"re","value":"secret="}],"action":"LOG"}
{"id":"tmp-badregex","if":["AND",{"cond":"uri","op":"prefix","value":"/badregex"},{"cond":"uri","op":"re","value":"["}],"action":"BLOCK"}
EOF
sleep 3
test_rule "combo LOG no block" 200 -A "Mozilla/5.0" "$TARGET/CITEST?SECRET=1"
test_rule "combo bad regex skipped" 200 -A "Mozilla/5.0" "$TARGET/badregex"
test_rule "combo SCORE threshold 0" 200 -A "Mozilla/5.0" "$TARGET/scoretest"
test_rule "combo L1 url + legacy block" 403 -A "Mozilla/5.0" "$TARGET/etc/passwd"

if log_has '"rule_tag":"tmp-ci-re"'; then PASS=$((PASS+1)); echo "  PASS  combo case-insensitive re log"; else FAIL=$((FAIL+1)); echo "  FAIL  combo case-insensitive re log"; fi
if log_has '"attack_method":"Combo_LOG"'; then PASS=$((PASS+1)); echo "  PASS  Combo_LOG logged"; else FAIL=$((FAIL+1)); echo "  FAIL  Combo_LOG missing"; fi
if log_has '"attack_method":"Combo_SCORE"'; then PASS=$((PASS+1)); echo "  PASS  Combo_SCORE logged"; else FAIL=$((FAIL+1)); echo "  FAIL  Combo_SCORE missing"; fi
if log_has '"attack_method":"Deny_URL"'; then PASS=$((PASS+1)); echo "  PASS  legacy Deny_URL logged via cache"; else FAIL=$((FAIL+1)); echo "  FAIL  legacy Deny_URL missing"; fi

sed -i 's/"score_block_threshold":0/"score_block_threshold":1/' "$RULE_DIR/config.json"
sleep 3
test_rule "combo SCORE threshold 1" 403 -A "Mozilla/5.0" "$TARGET/scoretest"
if log_has '"attack_method":"Combo_SCORE_BLOCK"'; then PASS=$((PASS+1)); echo "  PASS  Combo_SCORE_BLOCK logged"; else FAIL=$((FAIL+1)); echo "  FAIL  Combo_SCORE_BLOCK missing"; fi

echo ""
echo "========================================"
echo "  PASS: $PASS  FAIL: $FAIL"
echo "========================================"
if [ "$FAIL" -gt 0 ]; then
    echo -e "失败项:$ERRORS"
    exit 1
fi
