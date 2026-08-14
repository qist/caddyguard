#!/bin/bash
# CaddyGuard 规则全量测试
# 在 180 本地执行，验证各类攻击规则是否正确拦截

set -e

CADDY="/opt/caddyguard/caddy"
CONF_DIR="/opt/caddyguard/test-config"
RULE_DIR="/opt/caddyguard/rule-config"
TARGET="http://127.0.0.1:8888"
PASS=0
FAIL=0
ERRORS=""

# 停掉旧进程
kill $(pgrep -x caddy) 2>/dev/null || true
sleep 1

# 启动后端
nohup $CADDY run --config $CONF_DIR/Caddyfile.backend --adapter caddyfile > /tmp/caddy_backend.log 2>&1 &
sleep 1

# 部署全开配置（不含 CC）
cat > $RULE_DIR/config.json << 'EOF'
{"waf_enable":"on","trust_proxy_headers":"on","log_dir":"/tmp","white_url_check":"on","white_ip_check":"on","white_ua_check":"on","black_ip_check":"on","url_check":"on","url_args_check":"on","user_agent_check":"on","cookie_check":"on","cc_check":"off","cc_rate":"999999/60","cc_block_ttl":0,"post_check":"on","referer_check":"off","file_upload_check":"on","waf_output":"html","waf_redirect_url":""}
EOF
sleep 3

# 启动 WAF Caddy
nohup $CADDY run --config $CONF_DIR/Caddyfile.WAF --adapter caddyguardfile > /tmp/caddy_waf.log 2>&1 &
sleep 2

# 验证启动
code=$(curl -s -m 5 -o /dev/null -w "%{http_code}" -H "User-Agent: Mozilla/5.0" $TARGET/)
if [ "$code" != "200" ]; then
    echo "FATAL: Caddy failed to start, HTTP $code"
    tail -20 /tmp/caddy_waf.log
    exit 1
fi
echo "Caddy started OK (HTTP 200)"
echo ""

# 测试函数
# $1 = 测试名称, $2 = 期望状态码, $3 = curl 参数...
test_rule() {
    local name="$1"
    local expect="$2"
    shift 2
    local actual=$(curl -s -m 5 -o /dev/null -w "%{http_code}" "$@")
    if [ "$actual" = "$expect" ]; then
        echo "  PASS  $name  (HTTP $actual)"
        PASS=$((PASS+1))
    else
        echo "  FAIL  $name  (got $actual, want $expect)"
        FAIL=$((FAIL+1))
        ERRORS="$ERRORS\n  $name: got $actual, want $expect"
    fi
}

echo "========================================"
echo "  CaddyGuard 规则全量测试"
echo "  $(date '+%Y-%m-%d %H:%M:%S')"
echo "========================================"
echo ""

# ===== 正常请求（期望 200）=====
echo "--- 正常请求 ---"
test_rule "Normal GET" 200 -H "User-Agent: Mozilla/5.0" "$TARGET/"
test_rule "Normal Args" 200 -H "User-Agent: Mozilla/5.0" "$TARGET/?id=123&name=hello"
test_rule "Normal POST" 200 -H "User-Agent: Mozilla/5.0" -d "test=hello_world_data_padding" "$TARGET/"

# ===== URL 路径检测 =====
echo "--- URL 路径检测 ---"
test_rule "Path /etc/passwd" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/etc/passwd"
test_rule "Path /.env" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/.env"
test_rule "Path /wp-admin/" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/wp-admin/"
test_rule "Path / actuator" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/actuator/env"
test_rule "Path /.git/" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/.git/config"

# ===== URL 参数检测 (args.rule) =====
echo "--- URL 参数检测 ---"
test_rule "SQL union select" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?id=1+union+select+1"
test_rule "SQL sleep()" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?id=sleep(5)"
test_rule "SQL benchmark()" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?id=benchmark(1000000,md5(1))"
test_rule "XSS <script>" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=<script>alert(1)</script>"
test_rule "XSS <iframe>" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=<iframe>test</iframe>"
test_rule "Path traversal" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?file=../../../etc/passwd"
test_rule "NoSQL \$where" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=\$where(1==1)"
test_rule "SSTI {{__class__}}" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=%7B%7B__class__%7D%7D"
test_rule "javascript: protocol" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=javascript:alert(1)"
test_rule "base64_decode" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=base64_decode(aGVsbG8=)"

# ===== User-Agent 检测 =====
echo "--- User-Agent 检测 ---"
test_rule "UA sqlmap" 403 -A "sqlmap/1.0" "$TARGET/"
test_rule "UA nikto" 403 -A "Nikto/2.1.6" "$TARGET/"
test_rule "UA nmap" 403 -A "Nmap Scripting Engine" "$TARGET/"
test_rule "UA dirbuster" 403 -A "DirBuster" "$TARGET/"
test_rule "UA masscan" 403 -A "masscan/1.0" "$TARGET/"

# ===== Cookie 检测 =====
echo "--- Cookie 检测 ---"
test_rule "Cookie SQL injection" 403 -H "User-Agent: Mozilla/5.0" -b "id=1 union select 1" "$TARGET/"
test_rule "Cookie XSS" 403 -H "User-Agent: Mozilla/5.0" -b "q=<script>alert(1)</script>" "$TARGET/"
test_rule "Cookie path traversal" 403 -H "User-Agent: Mozilla/5.0" -b "file=../../../etc/passwd" "$TARGET/"

# ===== POST body 检测 =====
echo "--- POST body 检测 ---"
test_rule "POST SQL union" 403 -H "User-Agent: Mozilla/5.0" -d "id=1 union select 1" "$TARGET/"
test_rule "POST XSS script" 403 -H "User-Agent: Mozilla/5.0" -d "q=<script>alert(1)</script>" "$TARGET/"
test_rule "POST path traversal" 403 -H "User-Agent: Mozilla/5.0" -d "file=../../../etc/passwd" "$TARGET/"
test_rule "POST base64_decode" 403 -H "User-Agent: Mozilla/5.0" -d "x=base64_decode(aGVsbG8=)" "$TARGET/"
test_rule "POST \$_GET" 403 -H "User-Agent: Mozilla/5.0" -d 'x=$_GET[cmd]' "$TARGET/"
test_rule "POST \$_POST" 403 -H "User-Agent: Mozilla/5.0" -d 'y=$_POST[data]' "$TARGET/"
test_rule "POST eval()" 403 -H "User-Agent: Mozilla/5.0" -d "x=eval(base64_decode(aGVsbG8=))" "$TARGET/"
test_rule "POST system()" 403 -H "User-Agent: Mozilla/5.0" -d "x=system(ls)" "$TARGET/"
test_rule "POST child_process" 403 -H "User-Agent: Mozilla/5.0" -d "x=require('child_process')" "$TARGET/"
test_rule "POST SSTI" 403 -H "User-Agent: Mozilla/5.0" -d 'x={{__class__}}' "$TARGET/"
test_rule "POST NoSQL \$eq(" 403 -H "User-Agent: Mozilla/5.0" -d 'x=$eq(1)' "$TARGET/"
test_rule "POST sleep()" 403 -H "User-Agent: Mozilla/5.0" -d "id=sleep(5)" "$TARGET/"
test_rule "POST javascript:" 403 -H "User-Agent: Mozilla/5.0" -d "q=javascript:alert(1)" "$TARGET/"
test_rule "POST CONCAT()" 403 -H "User-Agent: Mozilla/5.0" -d 'x=CONCAT(user(),0x3a)' "$TARGET/"
test_rule "POST concat() lowercase" 403 -H "User-Agent: Mozilla/5.0" -d 'x=concat(user(),0x3a)' "$TARGET/"

# ===== 正常 POST（期望 200）=====
echo "--- 正常 POST（不命中规则）---"
test_rule "Normal POST 1" 200 -H "User-Agent: Mozilla/5.0" -d "username=admin&password=test123" "$TARGET/"
test_rule "Normal POST 2" 200 -H "User-Agent: Mozilla/5.0" -d "action=login&token=abc123def456" "$TARGET/"
test_rule "Normal POST 3" 200 -H "User-Agent: Mozilla/5.0" -d "message=hello_world_data_padding" "$TARGET/"

# ===== 汇总 =====
echo ""
echo "========================================"
echo "  测试结果汇总"
echo "  PASS: $PASS  FAIL: $FAIL"
echo "========================================"
if [ $FAIL -gt 0 ]; then
    echo -e "失败项:$ERRORS"
fi

# 清理
kill $(pgrep -x caddy) 2>/dev/null || true
echo "Done!"
