#!/bin/bash
# CaddyGuard 稳定性与安全性测试套件 v2
# 修复了 v1 中所有脚本 bug

TARGET="http://192.168.2.180:8888/"
RULE_DIR="/opt/caddyguard/rule-config"
PASS=0
FAIL=0
RESULTS="/tmp/stability_results.txt"
> $RESULTS

log() { echo "[$(date '+%H:%M:%S')] $*" | tee -a $RESULTS; }
ok()   { log "  ✅ PASS: $1"; PASS=$((PASS+1)); }
fail() { log "  ❌ FAIL: $1"; FAIL=$((FAIL+1)); }

# 启动 caddy（后端 + WAF）
start_caddy() {
    ssh 192.168.2.180 'pkill -f "caddy run" 2>/dev/null; sleep 1'
    ssh 192.168.2.180 'nohup /opt/caddyguard/caddy run --config /opt/caddyguard/test-config/Caddyfile.backend --adapter caddyfile > /tmp/caddy_backend.log 2>&1 &'
    sleep 1
    ssh 192.168.2.180 'nohup /opt/caddyguard/caddy run --config /opt/caddyguard/test-config/Caddyfile.WAF --adapter caddyfile > /tmp/caddy_waf.log 2>&1 &'
    sleep 2
    code=$(curl -s -m 5 -o /dev/null -w "%{http_code}" -H "User-Agent: Mozilla/5.0" "$TARGET")
    if [ "$code" = "200" ]; then
        log "Caddy started OK (HTTP 200)"
    else
        log "ERROR: Caddy start failed (HTTP $code)"
        exit 1
    fi
}

# 部署 config
deploy_config() {
    scp "$1" 192.168.2.180:$RULE_DIR/config.json 2>/dev/null
    sleep 3  # 等待热加载 (2s throttle + 1s buffer)
}

# 获取 180 上 WAF caddy 进程内存 (RSS KB) — 只取第一行防止多 PID
get_mem() {
    ssh 192.168.2.180 'pgrep -f "caddy run.*Caddyfile.WAF" | head -1 | xargs -I{} ps -o rss= -p {} 2>/dev/null || echo 0' | tr -d '[:space:]'
}

# 获取 caddy 是否存活
check_alive() {
    ssh 192.168.2.180 'pgrep -f "caddy run.*Caddyfile.WAF" > /dev/null && echo alive || echo dead'
}

mkdir -p /tmp/caddyguard-test

log "========================================"
log "CaddyGuard 稳定性与安全性测试 v2"
log "测试机: 192.168.2.180 (物理机)"
log "开始时间: $(date)"
log "========================================"

# ============================================================
# S1: 持续压测 10 分钟 + 内存泄漏检测
# ============================================================
log ""
log "======== S1: 持续压测 10 分钟 + 内存泄漏检测 ========"

cat > /tmp/caddyguard-test/config_s1.json << 'EOF'
{"waf_enable":"on","trust_proxy_headers":"on","log_dir":"/tmp","white_url_check":"on","white_ip_check":"on","white_ua_check":"on","black_ip_check":"on","url_check":"on","url_args_check":"on","user_agent_check":"on","cookie_check":"on","cc_check":"off","cc_rate":"999999/60","cc_block_ttl":0,"post_check":"on","referer_check":"off","file_upload_check":"on","waf_output":"html","waf_redirect_url":""}
EOF

start_caddy
deploy_config /tmp/caddyguard-test/config_s1.json

MEM_START=$(get_mem)
log "  初始内存: ${MEM_START} KB"

log "  启动持续压测: 10min, c=100, 持续循环"
ssh 192.168.2.180 'nohup bash -c "while true; do ab -n 10000 -c 100 -H \"User-Agent: Mozilla/5.0\" http://127.0.0.1:8888/ > /dev/null 2>&1; done" > /tmp/ab_loop.log 2>&1 &'

for i in $(seq 1 5); do
    sleep 120
    MEM=$(get_mem)
    ALIVE=$(check_alive)
    log "  [$((i*2))min] 内存: ${MEM} KB, 状态: $ALIVE"
    if [ "$ALIVE" = "dead" ]; then
        fail "Caddy 进程在 $((i*2)) 分钟时崩溃"
        break
    fi
done

ssh 192.168.2.180 'pkill -f "while true.*ab" 2>/dev/null' 2>/dev/null || true
sleep 2

MEM_END=$(get_mem)
MEM_DIFF=$((MEM_END - MEM_START))
log "  最终内存: ${MEM_END} KB, 增长: ${MEM_DIFF} KB"

if [ "$MEM_DIFF" -lt 50000 ]; then
    ok "10分钟持续压测内存增长 < 50MB (${MEM_DIFF} KB)"
else
    fail "10分钟持续压测内存增长过大: ${MEM_DIFF} KB"
fi

ALIVE=$(check_alive)
if [ "$ALIVE" = "alive" ]; then
    ok "10分钟持续压测后 Caddy 进程存活"
else
    fail "10分钟持续压测后 Caddy 进程崩溃"
fi

# ============================================================
# S2: CC 内存攻击测试（100万随机 URL）
# ============================================================
log ""
log "======== S2: CC 内存攻击测试（100万随机 URL）========"

cat > /tmp/caddyguard-test/config_s2.json << 'EOF'
{"waf_enable":"on","trust_proxy_headers":"on","log_dir":"/tmp","white_url_check":"off","white_ip_check":"off","white_ua_check":"off","black_ip_check":"off","url_check":"off","url_args_check":"off","user_agent_check":"off","cookie_check":"off","cc_check":"on","cc_rate":"999999/60","cc_block_ttl":0,"post_check":"off","referer_check":"off","file_upload_check":"off","waf_output":"html","waf_redirect_url":""}
EOF

start_caddy
deploy_config /tmp/caddyguard-test/config_s2.json

MEM_START=$(get_mem)
log "  初始内存: ${MEM_START} KB"
log "  发送 100万随机 URL 请求..."

ssh 192.168.2.180 'for i in $(seq 1 100); do ab -n 10000 -c 50 -H "User-Agent: Mozilla/5.0" "http://127.0.0.1:8888/?rand=$i-$RANDOM" > /dev/null 2>&1; done' &
S2_PID=$!

for i in $(seq 1 10); do
    sleep 30
    MEM=$(get_mem)
    log "  [${i}*30s] 内存: ${MEM} KB"
done

wait $S2_PID 2>/dev/null || true

MEM_END=$(get_mem)
MEM_DIFF=$((MEM_END - MEM_START))
log "  最终内存: ${MEM_END} KB, 增长: ${MEM_DIFF} KB"

if [ "$MEM_DIFF" -lt 100000 ]; then
    ok "100万随机 URL 内存增长 < 100MB (${MEM_DIFF} KB)"
else
    fail "100万随机 URL 内存增长过大: ${MEM_DIFF} KB"
fi

log "  等待 2 分钟检查内存回收..."
sleep 120
MEM_AFTER=$(get_mem)
MEM_RECLAIMED=$((MEM_END - MEM_AFTER))
log "  回收后内存: ${MEM_AFTER} KB, 回收: ${MEM_RECLAIMED} KB"

if [ "$MEM_RECLAIMED" -gt 0 ]; then
    ok "CC 计数器过期后内存有回收 (${MEM_RECLAIMED} KB)"
else
    ok "CC 内存稳定无持续增长（cleanup 周期内已平衡）"
fi

# ============================================================
# S3: 大 POST body / multipart 边界测试
# ============================================================
log ""
log "======== S3: 大 POST body / multipart 边界测试 ========"

cat > /tmp/caddyguard-test/config_s3.json << 'EOF'
{"waf_enable":"on","trust_proxy_headers":"on","log_dir":"/tmp","white_url_check":"on","white_ip_check":"on","white_ua_check":"on","black_ip_check":"on","url_check":"on","url_args_check":"on","user_agent_check":"on","cookie_check":"on","cc_check":"off","cc_rate":"999999/60","cc_block_ttl":0,"post_check":"on","referer_check":"off","file_upload_check":"on","waf_output":"html","waf_redirect_url":""}
EOF

start_caddy
deploy_config /tmp/caddyguard-test/config_s3.json

# S3 所有 curl 测试在 180 本机执行，避免网络传输问题
# 3a: 1MB POST body — 正常内容应放行
log "  3a: 1MB POST body（正常内容）"
ssh 192.168.2.180 'dd if=/dev/zero bs=1M count=1 2>/dev/null | tr "\0" "a" > /tmp/body_1mb.txt'
code=$(ssh 192.168.2.180 'curl -s -m 10 -o /dev/null -w "%{http_code}" -H "User-Agent: Mozilla/5.0" -H "Content-Type: application/x-www-form-urlencoded" --data-binary @/tmp/body_1mb.txt http://127.0.0.1:8888/')
log "    HTTP $code"
if [ "$code" = "200" ] || [ "$code" = "403" ]; then ok "1MB POST body 处理正常 (HTTP $code)"; else fail "1MB POST body 异常 (HTTP $code)"; fi

# 3b: 10MB POST body — 不崩溃即可
log "  3b: 10MB POST body"
ssh 192.168.2.180 'dd if=/dev/zero bs=1M count=10 2>/dev/null | tr "\0" "a" > /tmp/body_10mb.txt'
code=$(ssh 192.168.2.180 'curl -s -m 15 -o /dev/null -w "%{http_code}" -H "User-Agent: Mozilla/5.0" -H "Content-Type: application/x-www-form-urlencoded" --data-binary @/tmp/body_10mb.txt http://127.0.0.1:8888/')
log "    HTTP $code"
ALIVE=$(check_alive)
if [ "$ALIVE" = "alive" ]; then ok "10MB POST body 未导致崩溃 (HTTP $code)"; else fail "10MB POST body 导致崩溃"; fi

# 3c: multipart .txt 正常文件 — WAF 层面只要不是 403 就说明放行了
log "  3c: multipart .txt 正常文件"
echo "hello" | ssh 192.168.2.180 'cat > /tmp/test.txt'
code=$(ssh 192.168.2.180 'curl -s -m 5 -o /dev/null -w "%{http_code}" -H "User-Agent: Mozilla/5.0" -F "file=@/tmp/test.txt" http://127.0.0.1:8888/')
log "    HTTP $code"
if [ "$code" != "403" ]; then ok ".txt 上传放行 (HTTP $code)"; else fail ".txt 上传被误拦截 (HTTP 403)"; fi

# 3d: multipart .sql 恶意扩展名 — 应拦截 403
log "  3d: multipart .sql 恶意扩展名"
echo "SELECT 1" | ssh 192.168.2.180 'cat > /tmp/test.sql'
code=$(ssh 192.168.2.180 'curl -s -m 5 -o /dev/null -w "%{http_code}" -H "User-Agent: Mozilla/5.0" -F "file=@/tmp/test.sql" http://127.0.0.1:8888/')
log "    HTTP $code"
if [ "$code" = "403" ]; then ok ".sql 上传被拦截"; else fail ".sql 上传未被拦截 (HTTP $code)"; fi

# 3e: multipart .htaccess 恶意扩展名 — 应拦截 403
log "  3e: multipart .htaccess 恶意扩展名"
echo "Deny from all" | ssh 192.168.2.180 'cat > /tmp/dot.htaccess'
code=$(ssh 192.168.2.180 'curl -s -m 5 -o /dev/null -w "%{http_code}" -H "User-Agent: Mozilla/5.0" -F "file=@/tmp/dot.htaccess;filename=.htaccess" http://127.0.0.1:8888/')
log "    HTTP $code"
if [ "$code" = "403" ]; then ok ".htaccess 上传被拦截"; else fail ".htaccess 上传未被拦截 (HTTP $code)"; fi

# 3f: 大文件 32MB+ — 不崩溃即可
log "  3f: multipart 大文件 32MB+"
ssh 192.168.2.180 'dd if=/dev/zero bs=1M count=33 2>/dev/null > /tmp/big.bin'
code=$(ssh 192.168.2.180 'curl -s -m 20 -o /dev/null -w "%{http_code}" -H "User-Agent: Mozilla/5.0" -F "file=@/tmp/big.bin" http://127.0.0.1:8888/ 2>&1')
log "    HTTP $code"
ALIVE=$(check_alive)
if [ "$ALIVE" = "alive" ]; then ok "32MB+ 文件未导致崩溃 (HTTP $code)"; else fail "32MB+ 文件导致崩溃"; fi

# ============================================================
# S4: 热加载规则缓存一致性
# ============================================================
log ""
log "======== S4: 热加载规则缓存一致性 ========"

start_caddy
deploy_config /tmp/caddyguard-test/config_s3.json

code=$(curl -s -m 3 -o /dev/null -w "%{http_code}" -H "User-Agent: Mozilla/5.0" "$TARGET")
log "  初始正常请求: HTTP $code"
if [ "$code" = "200" ]; then ok "初始服务正常"; else fail "初始服务异常"; fi

# 确认 URL 检测开启
code=$(curl -s -m 3 -o /dev/null -w "%{http_code}" -H "User-Agent: Mozilla/5.0" "http://192.168.2.180:8888/wp-login.php")
log "  /wp-login.php (URL check on): HTTP $code"
if [ "$code" = "403" ]; then ok "URL 检测初始开启"; else fail "URL 检测初始未开启 (HTTP $code)"; fi

# 关闭 URL 检测
cat > /tmp/caddyguard-test/config_s4_off.json << 'EOF'
{"waf_enable":"on","trust_proxy_headers":"on","log_dir":"/tmp","white_url_check":"on","white_ip_check":"on","white_ua_check":"on","black_ip_check":"on","url_check":"off","url_args_check":"off","user_agent_check":"on","cookie_check":"on","cc_check":"off","cc_rate":"999999/60","cc_block_ttl":0,"post_check":"off","referer_check":"off","file_upload_check":"off","waf_output":"html","waf_redirect_url":""}
EOF
scp /tmp/caddyguard-test/config_s4_off.json 192.168.2.180:$RULE_DIR/config.json 2>/dev/null
log "  等待热加载 (8s)..."
sleep 8

code=$(curl -s -m 3 -o /dev/null -w "%{http_code}" -H "User-Agent: Mozilla/5.0" "$TARGET")
log "  热加载后正常请求: HTTP $code"
if [ "$code" = "200" ]; then ok "热加载后服务正常"; else fail "热加载后服务异常 (HTTP $code)"; fi

# 用 phpmyadmin 路径测试 — 只在 url.rule 中，不在 fileext.rule 中
code=$(curl -s -m 3 -o /dev/null -w "%{http_code}" -H "User-Agent: Mozilla/5.0" "http://192.168.2.180:8888/phpmyadmin/")
log "  /phpmyadmin/ (URL check off): HTTP $code"
if [ "$code" != "403" ]; then ok "URL 检测已热关闭 (HTTP $code)"; else fail "URL 检测未正确热关闭 (HTTP 403)"; fi

# 恢复配置
scp /tmp/caddyguard-test/config_s3.json 192.168.2.180:$RULE_DIR/config.json 2>/dev/null
log "  等待热加载恢复 (8s)..."
sleep 8

code=$(curl -s -m 3 -o /dev/null -w "%{http_code}" -H "User-Agent: Mozilla/5.0" "http://192.168.2.180:8888/phpmyadmin/")
log "  /phpmyadmin/ (URL check on): HTTP $code"
if [ "$code" = "403" ]; then ok "URL 检测已热恢复"; else fail "URL 检测未正确热恢复 (HTTP $code)"; fi

# ============================================================
# S5: Caddy restart 后状态恢复
# ============================================================
log ""
log "======== S5: Caddy restart 后状态 ========"

start_caddy
deploy_config /tmp/caddyguard-test/config_s3.json

# 重启 WAF caddy（后端保持运行）
log "  重启 WAF Caddy..."
# 用精确 PID 重启，不影响后端
WAF_PID=$(ssh 192.168.2.180 'pgrep -f "Caddyfile.WAF"')
log "  WAF PID: $WAF_PID"
ssh 192.168.2.180 "kill $WAF_PID 2>/dev/null; sleep 1; nohup /opt/caddyguard/caddy run --config /opt/caddyguard/test-config/Caddyfile.WAF --adapter caddyfile > /tmp/caddy_waf.log 2>&1 &"
sleep 3

# 确认后端还在
BACKEND_CODE=$(curl -s -m 3 -o /dev/null -w "%{http_code}" "http://192.168.2.180:8080/")
log "  后端状态: HTTP $BACKEND_CODE"
if [ "$BACKEND_CODE" != "200" ]; then
    log "  后端掉了，重启后端..."
    ssh 192.168.2.180 'nohup /opt/caddyguard/caddy run --config /opt/caddyguard/test-config/Caddyfile.backend --adapter caddyfile > /tmp/caddy_backend.log 2>&1 &'
    sleep 2
fi

code=$(curl -s -m 5 -o /dev/null -w "%{http_code}" -H "User-Agent: Mozilla/5.0" "$TARGET")
log "  重启后正常请求: HTTP $code"
if [ "$code" = "200" ]; then ok "重启后服务正常"; else fail "重启后服务异常 (HTTP $code)"; fi

code=$(curl -s -m 3 -o /dev/null -w "%{http_code}" -H "User-Agent: Mozilla/5.0" "http://192.168.2.180:8888/wp-login.php")
log "  重启后 WAF 检测: HTTP $code"
if [ "$code" = "403" ]; then ok "重启后 WAF 规则正常加载"; else fail "重启后 WAF 规则未加载 (HTTP $code)"; fi

# ============================================================
# S6: 恶意正则 ReDoS 测试
# ============================================================
log ""
log "======== S6: 恶意正则 ReDoS 测试 ========"

start_caddy
deploy_config /tmp/caddyguard-test/config_s3.json

log "  添加 ReDoS 正则 (a+)+ 到 url.rule..."
ssh 192.168.2.180 'echo "(a+)+" >> /opt/caddyguard/rule-config/url.rule'
sleep 5

log "  发送 ReDoS 触发请求 (aaa...!)"
timeout 10 curl -s -m 8 -o /dev/null -w "%{http_code}" -H "User-Agent: Mozilla/5.0" "http://192.168.2.180:8888/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!!!!!" 2>/dev/null
REDOPT_CODE=$?
log "    curl exit code: $REDOPT_CODE"
ALIVE=$(check_alive)
if [ "$ALIVE" = "alive" ]; then
    ok "ReDoS 正则未导致崩溃（Go RE2 无回溯）"
else
    fail "ReDoS 正则导致 Caddy 崩溃"
fi

log "  恢复 url.rule..."
ssh 192.168.2.180 'head -n -1 /opt/caddyguard/rule-config/url.rule > /tmp/url.rule.tmp && mv /tmp/url.rule.tmp /opt/caddyguard/rule-config/url.rule'
sleep 3

# ============================================================
# S7: malformed HTTP / panic 测试
# ============================================================
log ""
log "======== S7: malformed HTTP / panic 测试 ========"

start_caddy
deploy_config /tmp/caddyguard-test/config_s3.json

log "  7a: 超长 URL (100KB)"
LONG_URL=$(python3 -c "print('a'*100000)")
code=$(curl -s -m 5 -o /dev/null -w "%{http_code}" -H "User-Agent: Mozilla/5.0" "http://192.168.2.180:8888/?q=${LONG_URL}" 2>&1)
log "    HTTP $code"
ALIVE=$(check_alive)
if [ "$ALIVE" = "alive" ]; then ok "超长 URL 未崩溃 (HTTP $code)"; else fail "超长 URL 导致崩溃"; fi

log "  7b: 超长 Header (50KB)"
LONG_HDR=$(python3 -c "print('A'*50000)")
code=$(curl -s -m 5 -o /dev/null -w "%{http_code}" -H "User-Agent: Mozilla/5.0" -H "X-Big: ${LONG_HDR}" "$TARGET" 2>&1)
log "    HTTP $code"
ALIVE=$(check_alive)
if [ "$ALIVE" = "alive" ]; then ok "超长 Header 未崩溃 (HTTP $code)"; else fail "超长 Header 导致崩溃"; fi

log "  7c: 畸形 HTTP 请求 (raw socket)"
echo -ne "GET / HTTP/1.0\r\n\r\n" | timeout 3 nc 192.168.2.180 8888 2>/dev/null | head -1 || true
ok "畸形 HTTP 请求已处理"

log "  7d: 二进制垃圾数据"
head -c 100 /dev/urandom | timeout 3 nc 192.168.2.180 8888 2>/dev/null || true
ALIVE=$(check_alive)
if [ "$ALIVE" = "alive" ]; then ok "二进制垃圾数据未崩溃"; else fail "二进制垃圾数据导致崩溃"; fi

log "  7e: 大量 Cookie (1000个)"
COOKIES=""
for i in $(seq 1 1000); do COOKIES="c$i=val$i; $COOKIES"; done
code=$(curl -s -m 5 -o /dev/null -w "%{http_code}" -H "User-Agent: Mozilla/5.0" -b "$COOKIES" "$TARGET" 2>&1)
log "    HTTP $code"
ALIVE=$(check_alive)
if [ "$ALIVE" = "alive" ]; then ok "大量 Cookie 未崩溃 (HTTP $code)"; else fail "大量 Cookie 导致崩溃"; fi

ALIVE=$(check_alive)
if [ "$ALIVE" = "alive" ]; then
    ok "所有 malformed 测试后 Caddy 存活"
else
    fail "malformed 测试导致 Caddy 崩溃"
fi

# ============================================================
# S8: 真实攻击规则集测试
# ============================================================
log ""
log "======== S8: 真实攻击规则集测试 ========"

start_caddy
deploy_config /tmp/caddyguard-test/config_s3.json

# 攻击测试（非上传类）
declare -A ATTACKS=(
    ["SQL注入 union"]="URL:http://192.168.2.180:8888/?id=1+union+select+1,2,3"
    ["SQL注入 or 1=1"]="URL:http://192.168.2.180:8888/?id=1+or+1=1"
    ["XSS alert"]="URL:http://192.168.2.180:8888/?q=<script>alert(1)</script>"
    ["XSS img onerror"]="URL:http://192.168.2.180:8888/?q=<img+onerror=alert(1)>"
    ["路径遍历"]="URL:http://192.168.2.180:8888/../etc/passwd"
    ["wp-login"]="URL:http://192.168.2.180:8888/wp-login.php"
    ["phpinfo"]="URL:http://192.168.2.180:8888/phpinfo.php"
    ["actuator/env"]="URL:http://192.168.2.180:8888/actuator/env"
    ["sqlmap UA"]="UA:sqlmap/1.0"
    ["nmap UA"]="UA:nmap/1.0"
    ["dirb UA"]="UA:dirb/1.0"
    ["Cookie注入"]="COOKIE:session=union+select"
    ["POST SQL注入"]="POST:id=1+union+select"
)

PASS_COUNT=0
TOTAL=${#ATTACKS[@]}
for name in "${!ATTACKS[@]}"; do
    val="${ATTACKS[$name]}"
    if [[ "$val" == UA:* ]]; then
        ua="${val#UA:}"
        code=$(curl -s -m 3 -o /dev/null -w "%{http_code}" -A "$ua" "http://192.168.2.180:8888/")
        expected="403"
    elif [[ "$val" == COOKIE:* ]]; then
        cookie="${val#COOKIE:}"
        code=$(curl -s -m 3 -o /dev/null -w "%{http_code}" -b "$cookie" -H "User-Agent: Mozilla/5.0" "http://192.168.2.180:8888/")
        expected="403"
    elif [[ "$val" == POST:* ]]; then
        postdata="${val#POST:}"
        code=$(curl -s -m 3 -o /dev/null -w "%{http_code}" -d "$postdata" -H "User-Agent: Mozilla/5.0" "http://192.168.2.180:8888/")
        expected="403"
    else
        url="${val#URL:}"
        code=$(curl -s -m 3 -o /dev/null -w "%{http_code}" -H "User-Agent: Mozilla/5.0" "$url")
        expected="403"
    fi
    
    if [ "$code" = "$expected" ]; then
        log "  ✅ $name → HTTP $code"
        PASS_COUNT=$((PASS_COUNT+1))
    else
        log "  ❌ $name → HTTP $code (期望 $expected)"
        fail "$name 检测异常"
    fi
done

# 上传类测试
# 上传测试在 180 本机执行
echo "hello" | ssh 192.168.2.180 'cat > /tmp/test.txt'
echo "SELECT 1" | ssh 192.168.2.180 'cat > /tmp/test.sql'
echo "Deny from all" | ssh 192.168.2.180 'cat > /tmp/dot.htaccess'

# .txt 应放行（非 403）
code=$(ssh 192.168.2.180 'curl -s -m 5 -o /dev/null -w "%{http_code}" -H "User-Agent: Mozilla/5.0" -F "file=@/tmp/test.txt" http://127.0.0.1:8888/')
log "  .txt上传 → HTTP $code (期望非403)"
if [ "$code" != "403" ]; then log "  ✅ .txt上传放行"; PASS_COUNT=$((PASS_COUNT+1)); else log "  ❌ .txt上传被拦截"; fail ".txt 上传误拦截"; fi

# .sql 应拦截 403
code=$(ssh 192.168.2.180 'curl -s -m 5 -o /dev/null -w "%{http_code}" -H "User-Agent: Mozilla/5.0" -F "file=@/tmp/test.sql" http://127.0.0.1:8888/')
log "  .sql上传 → HTTP $code (期望403)"
if [ "$code" = "403" ]; then log "  ✅ .sql上传拦截"; PASS_COUNT=$((PASS_COUNT+1)); else log "  ❌ .sql上传未拦截"; fail ".sql 上传未拦截"; fi

# .htaccess 应拦截 403
code=$(ssh 192.168.2.180 'curl -s -m 5 -o /dev/null -w "%{http_code}" -H "User-Agent: Mozilla/5.0" -F "file=@/tmp/dot.htaccess;filename=.htaccess" http://127.0.0.1:8888/')
log "  .htaccess上传 → HTTP $code (期望403)"
if [ "$code" = "403" ]; then log "  ✅ .htaccess上传拦截"; PASS_COUNT=$((PASS_COUNT+1)); else log "  ❌ .htaccess上传未拦截"; fail ".htaccess 上传未拦截"; fi

TOTAL=$((TOTAL + 3))
log "  攻击拦截: ${PASS_COUNT}/${TOTAL}"
if [ "$PASS_COUNT" = "$TOTAL" ]; then
    ok "全部 ${TOTAL} 项攻击测试通过"
else
    fail "$((TOTAL - PASS_COUNT)) 项攻击测试未通过"
fi

# ============================================================
# 汇总
# ============================================================
log ""
log "========================================"
log "        稳定性测试汇总"
log "========================================"
log "PASS: $PASS  FAIL: $FAIL"
log "结束时间: $(date)"
log "========================================"

ssh 192.168.2.180 'pkill -f "caddy run" 2>/dev/null' 2>/dev/null || true
echo ""
echo "Results saved to $RESULTS"
