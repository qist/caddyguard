#!/bin/bash
# CaddyGuard 全场景压测 v4 - 在测试机 180 上本地执行
# 改进：
#   1. 精确进程管理(不误杀backend)
#   2. 无set-e，ab非零不中断
#   3. 并发梯度测试
#   4. 单项规则逐个测
#   5. CC 放最后（避免封IP影响后续场景）
#   6. 攻击场景日志统计加 sleep 等异步 flush
# 测试机: 192.168.2.180 (物理机) - Caddy + ab 都在本机跑

CADDY="/opt/caddyguard/caddy"
CONF_DIR="/opt/caddyguard/test-config"
RULE_DIR="/opt/caddyguard/rule-config"
LOG_FILE="/tmp/caddy_bench.log"
TARGET="http://127.0.0.1:8888/"
UA="User-Agent: Mozilla/5.0"

RESULT_FILE="/tmp/bench_results_v4.txt"
> $RESULT_FILE

# 精确杀掉监听 8888 端口的进程（不影响 backend 8080）
stop_test_caddy() {
    local pids=$(ss -tlnp 2>/dev/null | grep ':8888 ' | grep -oP 'pid=\K[0-9]+' | sort -u)
    if [ -n "$pids" ]; then
        echo "$pids" | xargs kill 2>/dev/null
        sleep 1
    fi
}

# 启动或复用 backend
start_backend() {
    local code=$(curl -s -m 2 -o /dev/null -w "%{http_code}" http://127.0.0.1:8080/ 2>/dev/null)
    if [ "$code" = "200" ]; then
        echo "Backend: already running (HTTP 200)"
        return 0
    fi
    nohup $CADDY run --config $CONF_DIR/Caddyfile.backend --adapter caddyfile > /tmp/caddy_backend.log 2>&1 &
    sleep 1
    code=$(curl -s -m 3 -o /dev/null -w "%{http_code}" http://127.0.0.1:8080/)
    if [ "$code" != "200" ]; then
        echo "FATAL: Backend failed to start (HTTP $code)"
        return 1
    fi
    echo "Backend: HTTP $code"
}

# 启动测试 caddy
start_test() {
    local caddyfile="$1"
    local adapter="${2:-caddyguardfile}"
    stop_test_caddy
    start_backend || return 1
    nohup $CADDY run --config "$caddyfile" --adapter "$adapter" > $LOG_FILE 2>&1 &
    sleep 2
    local code=$(curl -s -m 3 -o /dev/null -w "%{http_code}" -H "$UA" $TARGET)
    if [ "$code" != "200" ]; then
        echo "ERROR: test caddy HTTP $code"
        tail -5 $LOG_FILE
        return 1
    fi
    echo "Test caddy: HTTP $code"
}

deploy_config() {
    cp "$1" $RULE_DIR/config.json
    sleep 5
}

# 运行 ab 压测并输出结果
bench() {
    local label="$1"
    local requests="$2"
    local concurrency="$3"
    local extra_args="$4"
    local target_url="${5:-$TARGET}"
    local custom_ua="${6:-$UA}"
    local ab_out="/tmp/ab_${label}.txt"

    echo -n "  $label: ${requests}req c=${concurrency} ... "
    ab -n "$requests" -c "$concurrency" -H "$custom_ua" $extra_args "$target_url" > "$ab_out" 2>&1
    local ab_rc=$?

    local rps=$(grep "Requests per second" "$ab_out" | awk '{print $4}')
    local tpr=$(grep "Time per request.*mean\b" "$ab_out" | head -1 | awk '{print $4}')
    local fail=$(grep "Failed requests" "$ab_out" | awk '{print $3}')
    local p99=$(grep "99%" "$ab_out" | awk '{print $2}')

    if [ -z "$rps" ]; then
        echo "FAIL (ab rc=$ab_rc)"
        echo "$label: RPS=N/A TPR=N/A Fail=N/A P99=N/A" >> $RESULT_FILE
        return 1
    fi
    echo "RPS=$rps TPR=${tpr}ms Fail=$fail P99=${p99}ms"
    echo "$label: RPS=$rps TPR=${tpr}ms Fail=$fail P99=${p99}ms" >> $RESULT_FILE
}

echo "========================================"
echo "  CaddyGuard 全场景压测 v4"
echo "  $(date '+%Y-%m-%d %H:%M:%S')"
echo "========================================"
echo ""

# ============================================================
echo "######## 第一部分：核心场景对比 (5万请求, 并发200) ########"
echo ""

# 场景 A: 纯反代基准
echo "--- A: Caddy 纯反代（无 WAF 基准） ---"
start_test "$CONF_DIR/Caddyfile.A" caddyfile
bench "A-NoWAF" 50000 200

# 场景 B: WAF 全关
echo ""
echo "--- B: WAF 全关（waf_enable off） ---"
cat > /tmp/config_B.json << 'EOF'
{"waf_enable":"off","trust_proxy_headers":"on","log_dir":"/tmp","white_url_check":"off","white_ip_check":"off","white_ua_check":"off","black_ip_check":"off","url_check":"off","url_args_check":"off","user_agent_check":"off","cookie_check":"off","cc_check":"off","cc_rate":"999999/60","cc_block_ttl":0,"post_check":"off","referer_check":"off","file_upload_check":"off","waf_output":"html","waf_redirect_url":""}
EOF
deploy_config "/tmp/config_B.json"
start_test "$CONF_DIR/Caddyfile.WAF"
bench "B-WAF-off" 50000 200

# 场景 C: WAF 规则全开（不含 CC）
echo ""
echo "--- C: WAF 规则全开（不含 CC） ---"
cat > /tmp/config_C.json << 'EOF'
{"waf_enable":"on","trust_proxy_headers":"on","log_dir":"/tmp","white_url_check":"on","white_ip_check":"on","white_ua_check":"on","black_ip_check":"on","url_check":"on","url_args_check":"on","user_agent_check":"on","cookie_check":"on","cc_check":"off","cc_rate":"999999/60","cc_block_ttl":0,"post_check":"on","referer_check":"off","file_upload_check":"on","waf_output":"html","waf_redirect_url":""}
EOF
deploy_config "/tmp/config_C.json"
start_test "$CONF_DIR/Caddyfile.WAF"
bench "C-WAF-on-noCC" 50000 200

# 场景 E: 攻击请求 + 日志写入
echo ""
echo "--- E: WAF 攻击请求触发拦截 + 日志写入 ---"
cat > /tmp/config_E.json << 'EOF'
{"waf_enable":"on","trust_proxy_headers":"on","log_dir":"/var/log/caddyguard","white_url_check":"on","white_ip_check":"on","white_ua_check":"on","black_ip_check":"on","url_check":"on","url_args_check":"on","user_agent_check":"on","cookie_check":"on","cc_check":"off","cc_rate":"999999/60","cc_block_ttl":0,"post_check":"on","referer_check":"off","file_upload_check":"on","waf_output":"html","waf_redirect_url":""}
EOF
mkdir -p /var/log/caddyguard
rm -f /var/log/caddyguard/*_waf.log 2>/dev/null || true
deploy_config "/tmp/config_E.json"
start_test "$CONF_DIR/Caddyfile.WAF"
# 攻击 UA（sqlmap）被 WAF 直接拦截，不经过后端
bench "E1-WAF-attack-UA" 50000 200 "" "" "User-Agent: sqlmap/1.0"
# 等待同步日志写入完成
sleep 2
LOG_COUNT=$(cat /var/log/caddyguard/*_waf.log 2>/dev/null | wc -l)
echo "  WAF log entries: $LOG_COUNT" >> $RESULT_FILE
echo "  WAF log entries: $LOG_COUNT"

# 场景 F: POST body 压测
echo ""
echo "--- F: WAF + POST body ---"
deploy_config "/tmp/config_C.json"
start_test "$CONF_DIR/Caddyfile.WAF"
echo "test=hello_world_data_padding_padding_padding" > /tmp/post_data.txt
bench "F-WAF-POST" 50000 200 "-p /tmp/post_data.txt"

# ============================================================
echo ""
echo "######## 第二部分：单项规则性能对比 (5万请求, 并发200) ########"
echo ""

# 场景 I: 仅 URL 检测
echo "--- I: 仅 URL 检测 ---"
cat > /tmp/config_I.json << 'EOF'
{"waf_enable":"on","trust_proxy_headers":"on","log_dir":"/tmp","white_url_check":"off","white_ip_check":"off","white_ua_check":"off","black_ip_check":"off","url_check":"on","url_args_check":"off","user_agent_check":"off","cookie_check":"off","cc_check":"off","cc_rate":"999999/60","cc_block_ttl":0,"post_check":"off","referer_check":"off","file_upload_check":"off","waf_output":"html","waf_redirect_url":""}
EOF
deploy_config "/tmp/config_I.json"
start_test "$CONF_DIR/Caddyfile.WAF"
bench "I-URL-only" 50000 200

# 场景 J: URL + Args
echo ""
echo "--- J: URL + Args 检测 ---"
cat > /tmp/config_J.json << 'EOF'
{"waf_enable":"on","trust_proxy_headers":"on","log_dir":"/tmp","white_url_check":"off","white_ip_check":"off","white_ua_check":"off","black_ip_check":"off","url_check":"on","url_args_check":"on","user_agent_check":"off","cookie_check":"off","cc_check":"off","cc_rate":"999999/60","cc_block_ttl":0,"post_check":"off","referer_check":"off","file_upload_check":"off","waf_output":"html","waf_redirect_url":""}
EOF
deploy_config "/tmp/config_J.json"
start_test "$CONF_DIR/Caddyfile.WAF"
bench "J-URL+Args" 50000 200

# 场景 K: 仅 UA
echo ""
echo "--- K: 仅 UA 检测 ---"
cat > /tmp/config_K.json << 'EOF'
{"waf_enable":"on","trust_proxy_headers":"on","log_dir":"/tmp","white_url_check":"off","white_ip_check":"off","white_ua_check":"off","black_ip_check":"off","url_check":"off","url_args_check":"off","user_agent_check":"on","cookie_check":"off","cc_check":"off","cc_rate":"999999/60","cc_block_ttl":0,"post_check":"off","referer_check":"off","file_upload_check":"off","waf_output":"html","waf_redirect_url":""}
EOF
deploy_config "/tmp/config_K.json"
start_test "$CONF_DIR/Caddyfile.WAF"
bench "K-UA-only" 50000 200

# 场景 L: 仅 Cookie
echo ""
echo "--- L: 仅 Cookie 检测 ---"
cat > /tmp/config_L.json << 'EOF'
{"waf_enable":"on","trust_proxy_headers":"on","log_dir":"/tmp","white_url_check":"off","white_ip_check":"off","white_ua_check":"off","black_ip_check":"off","url_check":"off","url_args_check":"off","user_agent_check":"off","cookie_check":"on","cc_check":"off","cc_rate":"999999/60","cc_block_ttl":0,"post_check":"off","referer_check":"off","file_upload_check":"off","waf_output":"html","waf_redirect_url":""}
EOF
deploy_config "/tmp/config_L.json"
start_test "$CONF_DIR/Caddyfile.WAF"
bench "L-Cookie-only" 50000 200

# 场景 M: 仅 IP 黑白名单
echo ""
echo "--- M: 仅 IP 黑白名单 ---"
cat > /tmp/config_M.json << 'EOF'
{"waf_enable":"on","trust_proxy_headers":"on","log_dir":"/tmp","white_url_check":"off","white_ip_check":"on","white_ua_check":"off","black_ip_check":"on","url_check":"off","url_args_check":"off","user_agent_check":"off","cookie_check":"off","cc_check":"off","cc_rate":"999999/60","cc_block_ttl":0,"post_check":"off","referer_check":"off","file_upload_check":"off","waf_output":"html","waf_redirect_url":""}
EOF
deploy_config "/tmp/config_M.json"
start_test "$CONF_DIR/Caddyfile.WAF"
bench "M-IP-BW-only" 50000 200

# 场景 O: 仅 POST body
echo ""
echo "--- O: 仅 POST body 检测 ---"
cat > /tmp/config_O.json << 'EOF'
{"waf_enable":"on","trust_proxy_headers":"on","log_dir":"/tmp","white_url_check":"off","white_ip_check":"off","white_ua_check":"off","black_ip_check":"off","url_check":"off","url_args_check":"off","user_agent_check":"off","cookie_check":"off","cc_check":"off","cc_rate":"999999/60","cc_block_ttl":0,"post_check":"on","referer_check":"off","file_upload_check":"off","waf_output":"html","waf_redirect_url":""}
EOF
deploy_config "/tmp/config_O.json"
start_test "$CONF_DIR/Caddyfile.WAF"
bench "O-POST-only" 50000 200 "-p /tmp/post_data.txt"

# 场景 P: 仅白名单
echo ""
echo "--- P: 仅白名单检测 ---"
cat > /tmp/config_P.json << 'EOF'
{"waf_enable":"on","trust_proxy_headers":"on","log_dir":"/tmp","white_url_check":"on","white_ip_check":"on","white_ua_check":"on","black_ip_check":"off","url_check":"off","url_args_check":"off","user_agent_check":"off","cookie_check":"off","cc_check":"off","cc_rate":"999999/60","cc_block_ttl":0,"post_check":"off","referer_check":"off","file_upload_check":"off","waf_output":"html","waf_redirect_url":""}
EOF
deploy_config "/tmp/config_P.json"
start_test "$CONF_DIR/Caddyfile.WAF"
bench "P-Whitelist-only" 50000 200

# ============================================================
echo ""
echo "######## 第三部分：并发梯度测试（WAF全开, 不含CC） ########"
echo ""
deploy_config "/tmp/config_C.json"
start_test "$CONF_DIR/Caddyfile.WAF"
for c in 10 50 100 200 500; do
    bench "Grad-c${c}" 20000 $c
done

# ============================================================
echo ""
echo "######## 第四部分：路径级 WAF 开关对比 ########"
echo ""
deploy_config "/tmp/config_C.json"
start_test "$CONF_DIR/Caddyfile.PathBench" caddyguardfile
# WAF off 路径
bench "Path1-WAF-off-webhook" 50000 200 "" "http://127.0.0.1:8888/api/webhook/test"
bench "Path2-WAF-off-upload" 50000 200 "" "http://127.0.0.1:8888/upload/test"
# WAF on 路径（根路径）
bench "Path3-WAF-on-root" 50000 200

# ============================================================
echo ""
echo "######## 第五部分：CC 防护测试（放最后，避免封IP影响前面场景） ########"
echo ""
echo "--- D: WAF 全开 + 真实 CC（150req/60s） ---"
cat > /tmp/config_D.json << 'EOF'
{"waf_enable":"on","trust_proxy_headers":"on","log_dir":"/tmp","white_url_check":"on","white_ip_check":"on","white_ua_check":"on","black_ip_check":"on","url_check":"on","url_args_check":"on","user_agent_check":"on","cookie_check":"on","cc_check":"on","cc_rate":"150/60","cc_block_ttl":600,"post_check":"on","referer_check":"off","file_upload_check":"on","waf_output":"html","waf_redirect_url":""}
EOF
deploy_config "/tmp/config_D.json"
start_test "$CONF_DIR/Caddyfile.WAF"
# D1: 小批量不触发 CC（验证正常放行）
bench "D1-WAF+CC-100req" 100 10
# D2: 大批量触发 CC（预期大部分被拦截 403）
bench "D2-WAF+CC-50k" 50000 200

# ============================================================
echo ""
echo "========================================"
echo "        压测结果汇总 (物理机 180)"
echo "        $(date '+%Y-%m-%d %H:%M:%S')"
echo "========================================"
cat $RESULT_FILE
echo "========================================"

# 清理
stop_test_caddy
pids=$(ss -tlnp 2>/dev/null | grep ':8080 ' | grep -oP 'pid=\K[0-9]+' | sort -u)
if [ -n "$pids" ]; then
    echo "$pids" | xargs kill 2>/dev/null
fi
echo "All done!"
