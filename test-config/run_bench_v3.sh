#!/bin/bash
# CaddyGuard 全场景对比压测 v3 - 在测试机 180 上本地执行
# 新增：路径级 WAF 开关测试 + 单项规则逐个测试
# 测试机: 192.168.2.180 (物理机) - Caddy + ab 都在本机跑

set -e

CADDY="/opt/caddyguard/caddy"
CONF_DIR="/opt/caddyguard/test-config"
RULE_DIR="/opt/caddyguard/rule-config"
LOG_FILE="/tmp/caddy_bench.log"
TARGET="http://127.0.0.1:8888/"
REQUESTS=50000
CONCURRENCY=200
UA="User-Agent: Mozilla/5.0"
RESULT_FILE="/tmp/bench_results_v3.txt"
> $RESULT_FILE

stop_caddy() {
    pkill -f 'caddy run' 2>/dev/null || true
    sleep 1
}

start_backend() {
    nohup $CADDY run --config $CONF_DIR/Caddyfile.backend --adapter caddyfile > /tmp/caddy_backend.log 2>&1 &
    sleep 1
    code=$(curl -s -m 3 -o /dev/null -w "%{http_code}" http://127.0.0.1:8080/)
    echo "Backend: HTTP $code"
}

start_test() {
    local caddyfile="$1"
    local adapter="${2:-caddyguardfile}"
    stop_caddy
    start_backend
    nohup $CADDY run --config "$caddyfile" --adapter "$adapter" > $LOG_FILE 2>&1 &
    sleep 2
    code=$(curl -s -m 3 -o /dev/null -w "%{http_code}" -H "$UA" $TARGET)
    if [ "$code" != "200" ]; then
        echo "ERROR: test caddy HTTP $code"
        tail -5 $LOG_FILE
        return 1
    fi
    echo "Test caddy: HTTP $code"
}

deploy_config() {
    cp "$1" $RULE_DIR/config.json
    sleep 3
}

run_bench() {
    local label="$1"
    local extra_args="$2"
    local target_url="${3:-$TARGET}"
    echo "--- $label: ${REQUESTS} req, c=${CONCURRENCY} ---"
    ab -n $REQUESTS -c $CONCURRENCY -H "$UA" $extra_args "$target_url" 2>&1
}

parse_result() {
    local ab_file="$1"
    local label="$2"
    local result_file="$3"
    RPS=$(grep "Requests per second" "$ab_file" | awk '{print $4}')
    TPR=$(grep "Time per request.*mean\b" "$ab_file" | head -1 | awk '{print $4}')
    FAIL=$(grep "Failed requests" "$ab_file" | awk '{print $3}')
    P99=$(grep "99%" "$ab_file" | awk '{print $2}')
    TRANSFER=$(grep "Transfer rate" "$ab_file" | awk '{print $3}')
    echo "$label: RPS=$RPS TPR=${TPR}ms Failed=$FAIL P99=${P99}ms"
    echo "$label: RPS=$RPS TPR=${TPR}ms Failed=$Fail P99=${P99}ms" >> $result_file
}

# ============================================================
echo "========================================"
echo "  CaddyGuard 全场景压测 v3"
echo "  $(date '+%Y-%m-%d %H:%M:%S')"
echo "  Requests=$REQUESTS Concurrency=$CONCURRENCY"
echo "========================================"
echo ""

# ============================================================
echo "######## 场景 A: Caddy + reverse_proxy（无 WAF 基准） ########"
start_test "$CONF_DIR/Caddyfile.A" caddyfile
ab -n $REQUESTS -c $CONCURRENCY -H "$UA" $TARGET > /tmp/ab_A.txt 2>&1
parse_result /tmp/ab_A.txt "A: NoWAF" $RESULT_FILE

# ============================================================
echo ""
echo "######## 场景 B: WAF 全关（waf_enable off） ########"
cat > /tmp/config_B.json << 'EOF'
{"waf_enable":"off","trust_proxy_headers":"on","log_dir":"/tmp","white_url_check":"off","white_ip_check":"off","white_ua_check":"off","black_ip_check":"off","url_check":"off","url_args_check":"off","user_agent_check":"off","cookie_check":"off","cc_check":"off","cc_rate":"999999/60","cc_block_ttl":0,"post_check":"off","referer_check":"off","file_upload_check":"off","waf_output":"html","waf_redirect_url":""}
EOF
deploy_config "/tmp/config_B.json"
start_test "$CONF_DIR/Caddyfile.WAF"
ab -n $REQUESTS -c $CONCURRENCY -H "$UA" $TARGET > /tmp/ab_B.txt 2>&1
parse_result /tmp/ab_B.txt "B: WAF-off" $RESULT_FILE

# ============================================================
echo ""
echo "######## 场景 C: WAF 规则全开（不含 CC） ########"
cat > /tmp/config_C.json << 'EOF'
{"waf_enable":"on","trust_proxy_headers":"on","log_dir":"/tmp","white_url_check":"on","white_ip_check":"on","white_ua_check":"on","black_ip_check":"on","url_check":"on","url_args_check":"on","user_agent_check":"on","cookie_check":"on","cc_check":"off","cc_rate":"999999/60","cc_block_ttl":0,"post_check":"on","referer_check":"off","file_upload_check":"on","waf_output":"html","waf_redirect_url":""}
EOF
deploy_config "/tmp/config_C.json"
start_test "$CONF_DIR/Caddyfile.WAF"
ab -n $REQUESTS -c $CONCURRENCY -H "$UA" $TARGET > /tmp/ab_C.txt 2>&1
parse_result /tmp/ab_C.txt "C: WAF-on-noCC" $RESULT_FILE

# ============================================================
echo ""
echo "######## 场景 D: WAF 规则全开 + CC ########"
cat > /tmp/config_D.json << 'EOF'
{"waf_enable":"on","trust_proxy_headers":"on","log_dir":"/tmp","white_url_check":"on","white_ip_check":"on","white_ua_check":"on","black_ip_check":"on","url_check":"on","url_args_check":"on","user_agent_check":"on","cookie_check":"on","cc_check":"on","cc_rate":"999999/60","cc_block_ttl":0,"post_check":"on","referer_check":"off","file_upload_check":"on","waf_output":"html","waf_redirect_url":""}
EOF
deploy_config "/tmp/config_D.json"
start_test "$CONF_DIR/Caddyfile.WAF"
ab -n $REQUESTS -c $CONCURRENCY -H "$UA" $TARGET > /tmp/ab_D.txt 2>&1
parse_result /tmp/ab_D.txt "D: WAF+CC" $RESULT_FILE

# ============================================================
echo ""
echo "######## 场景 E: WAF + 攻击请求触发日志 ########"
cat > /tmp/config_E.json << 'EOF'
{"waf_enable":"on","trust_proxy_headers":"on","log_dir":"/var/log/caddyguard","white_url_check":"on","white_ip_check":"on","white_ua_check":"on","black_ip_check":"on","url_check":"on","url_args_check":"on","user_agent_check":"on","cookie_check":"on","cc_check":"off","cc_rate":"999999/60","cc_block_ttl":0,"post_check":"on","referer_check":"off","file_upload_check":"on","waf_output":"html","waf_redirect_url":""}
EOF
rm -f /var/log/caddyguard/*_waf.log 2>/dev/null || true
deploy_config "/tmp/config_E.json"
start_test "$CONF_DIR/Caddyfile.WAF"
ab -n $REQUESTS -c $CONCURRENCY -H "User-Agent: sqlmap/1.0" $TARGET > /tmp/ab_E.txt 2>&1
parse_result /tmp/ab_E.txt "E: WAF+log-attack" $RESULT_FILE
LOG_COUNT=$(wc -l < /var/log/caddyguard/*_waf.log 2>/dev/null || echo 0)
echo "  WAF log entries: $LOG_COUNT" >> $RESULT_FILE

# ============================================================
echo ""
echo "######## 场景 F: WAF + POST body ########"
deploy_config "/tmp/config_C.json"
start_test "$CONF_DIR/Caddyfile.WAF"
echo "test=hello_world_data_padding_padding_padding" > /tmp/post_data.txt
ab -n $REQUESTS -c $CONCURRENCY -H "$UA" -p /tmp/post_data.txt $TARGET > /tmp/ab_F.txt 2>&1
parse_result /tmp/ab_F.txt "F: WAF+POST" $RESULT_FILE

# ============================================================
echo ""
echo "######## 场景 G: 路径级 WAF 开关 - waf_enable off 路径 ########"
# 使用 Caddyfile.PathBench，路径 /api/webhook/* 关闭了 WAF
deploy_config "/tmp/config_C.json"
start_test "$CONF_DIR/Caddyfile.PathBench"
# 测试 waf_enable off 的路径（期望 200，不走 WAF 检测）
WEBHOOK_URL="http://127.0.0.1:8888/api/webhook/test"
code=$(curl -s -m 3 -o /dev/null -w "%{http_code}" -H "$UA" "$WEBHOOK_URL")
echo "  Verify webhook path: HTTP $code (expect 200)"
ab -n $REQUESTS -c $CONCURRENCY -H "$UA" "$WEBHOOK_URL" > /tmp/ab_G1.txt 2>&1
parse_result /tmp/ab_G1.txt "G1: PathWAF-off" $RESULT_FILE

# 测试 /upload/* 路径（也关闭了 WAF）
UPLOAD_URL="http://127.0.0.1:8888/upload/test"
code=$(curl -s -m 3 -o /dev/null -w "%{http_code}" -H "$UA" "$UPLOAD_URL")
echo "  Verify upload path: HTTP $code (expect 200)"
ab -n $REQUESTS -c $CONCURRENCY -H "$UA" "$UPLOAD_URL" > /tmp/ab_G2.txt 2>&1
parse_result /tmp/ab_G2.txt "G2: PathWAF-off-2" $RESULT_FILE

# ============================================================
echo ""
echo "######## 场景 H: 路径级 WAF 开关 - 同配置 WAF on 路径对比 ########"
# 同样使用 Caddyfile.PathBench，但测试 / 路径（WAF 开启）
ab -n $REQUESTS -c $CONCURRENCY -H "$UA" $TARGET > /tmp/ab_H.txt 2>&1
parse_result /tmp/ab_H.txt "H: PathWAF-on" $RESULT_FILE

# ============================================================
echo ""
echo "######## 场景 I: 仅 URL 检测 ########"
cat > /tmp/config_I.json << 'EOF'
{"waf_enable":"on","trust_proxy_headers":"on","log_dir":"/tmp","white_url_check":"off","white_ip_check":"off","white_ua_check":"off","black_ip_check":"off","url_check":"on","url_args_check":"off","user_agent_check":"off","cookie_check":"off","cc_check":"off","cc_rate":"999999/60","cc_block_ttl":0,"post_check":"off","referer_check":"off","file_upload_check":"off","waf_output":"html","waf_redirect_url":""}
EOF
deploy_config "/tmp/config_I.json"
start_test "$CONF_DIR/Caddyfile.WAF"
ab -n $REQUESTS -c $CONCURRENCY -H "$UA" $TARGET > /tmp/ab_I.txt 2>&1
parse_result /tmp/ab_I.txt "I: URL-only" $RESULT_FILE

# ============================================================
echo ""
echo "######## 场景 J: 仅 URL + URL参数 检测 ########"
cat > /tmp/config_J.json << 'EOF'
{"waf_enable":"on","trust_proxy_headers":"on","log_dir":"/tmp","white_url_check":"off","white_ip_check":"off","white_ua_check":"off","black_ip_check":"off","url_check":"on","url_args_check":"on","user_agent_check":"off","cookie_check":"off","cc_check":"off","cc_rate":"999999/60","cc_block_ttl":0,"post_check":"off","referer_check":"off","file_upload_check":"off","waf_output":"html","waf_redirect_url":""}
EOF
deploy_config "/tmp/config_J.json"
start_test "$CONF_DIR/Caddyfile.WAF"
ab -n $REQUESTS -c $CONCURRENCY -H "$UA" $TARGET > /tmp/ab_J.txt 2>&1
parse_result /tmp/ab_J.txt "J: URL+Args" $RESULT_FILE

# ============================================================
echo ""
echo "######## 场景 K: 仅 UA 检测 ########"
cat > /tmp/config_K.json << 'EOF'
{"waf_enable":"on","trust_proxy_headers":"on","log_dir":"/tmp","white_url_check":"off","white_ip_check":"off","white_ua_check":"off","black_ip_check":"off","url_check":"off","url_args_check":"off","user_agent_check":"on","cookie_check":"off","cc_check":"off","cc_rate":"999999/60","cc_block_ttl":0,"post_check":"off","referer_check":"off","file_upload_check":"off","waf_output":"html","waf_redirect_url":""}
EOF
deploy_config "/tmp/config_K.json"
start_test "$CONF_DIR/Caddyfile.WAF"
ab -n $REQUESTS -c $CONCURRENCY -H "$UA" $TARGET > /tmp/ab_K.txt 2>&1
parse_result /tmp/ab_K.txt "K: UA-only" $RESULT_FILE

# ============================================================
echo ""
echo "######## 场景 L: 仅 Cookie 检测 ########"
cat > /tmp/config_L.json << 'EOF'
{"waf_enable":"on","trust_proxy_headers":"on","log_dir":"/tmp","white_url_check":"off","white_ip_check":"off","white_ua_check":"off","black_ip_check":"off","url_check":"off","url_args_check":"off","user_agent_check":"off","cookie_check":"on","cc_check":"off","cc_rate":"999999/60","cc_block_ttl":0,"post_check":"off","referer_check":"off","file_upload_check":"off","waf_output":"html","waf_redirect_url":""}
EOF
deploy_config "/tmp/config_L.json"
start_test "$CONF_DIR/Caddyfile.WAF"
ab -n $REQUESTS -c $CONCURRENCY -H "$UA" $TARGET > /tmp/ab_L.txt 2>&1
parse_result /tmp/ab_L.txt "L: Cookie-only" $RESULT_FILE

# ============================================================
echo ""
echo "######## 场景 M: 仅 IP 黑白名单 ########"
cat > /tmp/config_M.json << 'EOF'
{"waf_enable":"on","trust_proxy_headers":"on","log_dir":"/tmp","white_url_check":"off","white_ip_check":"on","white_ua_check":"off","black_ip_check":"on","url_check":"off","url_args_check":"off","user_agent_check":"off","cookie_check":"off","cc_check":"off","cc_rate":"999999/60","cc_block_ttl":0,"post_check":"off","referer_check":"off","file_upload_check":"off","waf_output":"html","waf_redirect_url":""}
EOF
deploy_config "/tmp/config_M.json"
start_test "$CONF_DIR/Caddyfile.WAF"
ab -n $REQUESTS -c $CONCURRENCY -H "$UA" $TARGET > /tmp/ab_M.txt 2>&1
parse_result /tmp/ab_M.txt "M: IP-BW-only" $RESULT_FILE

# ============================================================
echo ""
echo "######## 场景 N: 仅 CC 检测 ########"
cat > /tmp/config_N.json << 'EOF'
{"waf_enable":"on","trust_proxy_headers":"on","log_dir":"/tmp","white_url_check":"off","white_ip_check":"off","white_ua_check":"off","black_ip_check":"off","url_check":"off","url_args_check":"off","user_agent_check":"off","cookie_check":"off","cc_check":"on","cc_rate":"999999/60","cc_block_ttl":0,"post_check":"off","referer_check":"off","file_upload_check":"off","waf_output":"html","waf_redirect_url":""}
EOF
deploy_config "/tmp/config_N.json"
start_test "$CONF_DIR/Caddyfile.WAF"
ab -n $REQUESTS -c $CONCURRENCY -H "$UA" $TARGET > /tmp/ab_N.txt 2>&1
parse_result /tmp/ab_N.txt "N: CC-only" $RESULT_FILE

# ============================================================
echo ""
echo "######## 场景 O: 仅 POST body 检测 ########"
cat > /tmp/config_O.json << 'EOF'
{"waf_enable":"on","trust_proxy_headers":"on","log_dir":"/tmp","white_url_check":"off","white_ip_check":"off","white_ua_check":"off","black_ip_check":"off","url_check":"off","url_args_check":"off","user_agent_check":"off","cookie_check":"off","cc_check":"off","cc_rate":"999999/60","cc_block_ttl":0,"post_check":"on","referer_check":"off","file_upload_check":"off","waf_output":"html","waf_redirect_url":""}
EOF
deploy_config "/tmp/config_O.json"
start_test "$CONF_DIR/Caddyfile.WAF"
ab -n $REQUESTS -c $CONCURRENCY -H "$UA" -p /tmp/post_data.txt $TARGET > /tmp/ab_O.txt 2>&1
parse_result /tmp/ab_O.txt "O: POST-only" $RESULT_FILE

# ============================================================
echo ""
echo "######## 场景 P: 仅白名单检测 ########"
cat > /tmp/config_P.json << 'EOF'
{"waf_enable":"on","trust_proxy_headers":"on","log_dir":"/tmp","white_url_check":"on","white_ip_check":"on","white_ua_check":"on","black_ip_check":"off","url_check":"off","url_args_check":"off","user_agent_check":"off","cookie_check":"off","cc_check":"off","cc_rate":"999999/60","cc_block_ttl":0,"post_check":"off","referer_check":"off","file_upload_check":"off","waf_output":"html","waf_redirect_url":""}
EOF
deploy_config "/tmp/config_P.json"
start_test "$CONF_DIR/Caddyfile.WAF"
ab -n $REQUESTS -c $CONCURRENCY -H "$UA" $TARGET > /tmp/ab_P.txt 2>&1
parse_result /tmp/ab_P.txt "P: Whitelist-only" $RESULT_FILE

# ============================================================
# 汇总
# ============================================================
echo ""
echo "========================================"
echo "        压测结果汇总 (物理机 180)"
echo "        $(date '+%Y-%m-%d %H:%M:%S')"
echo "========================================"
cat $RESULT_FILE
echo "========================================"

stop_caddy
echo "All done!"
