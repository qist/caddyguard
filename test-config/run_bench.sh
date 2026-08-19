#!/bin/bash
# CaddyGuard 全场景对比压测 - 在测试机 180 上本地执行
# 测试机: 192.168.2.180 (物理机) - Caddy + ab 都在本机跑

CADDY="/opt/caddyguard/caddy"
CONF_DIR="/opt/caddyguard/test-config"
RULE_DIR="/opt/caddyguard/rule-config"
LOG_FILE="/tmp/caddy_bench.log"
TARGET="http://127.0.0.1:8888/"
REQUESTS=50000
CONCURRENCY=200
UA="User-Agent: Mozilla/5.0"

RESULT_FILE="/tmp/bench_results.txt"
> $RESULT_FILE

stop_test_caddy() {
    # 只杀监听 8888 端口的 caddy 进程，不影响 backend(8080)
    pids=$(ss -tlnp | grep ':8888 ' | grep -oP 'pid=\K[0-9]+' | sort -u)
    if [ -n "$pids" ]; then
        echo "$pids" | xargs kill 2>/dev/null
        sleep 1
    fi
}

start_backend() {
    # 检查 backend 是否已在运行
    code=$(curl -s -m 2 -o /dev/null -w "%{http_code}" http://127.0.0.1:8080/ 2>/dev/null)
    if [ "$code" = "200" ]; then
        echo "Backend: already running (HTTP 200)"
        return 0
    fi
    nohup $CADDY run --config $CONF_DIR/Caddyfile.backend --adapter caddyfile > /tmp/caddy_backend.log 2>&1 &
    sleep 1
    code=$(curl -s -m 3 -o /dev/null -w "%{http_code}" http://127.0.0.1:8080/)
    echo "Backend: HTTP $code"
}

start_test() {
    local caddyfile="$1"
    local adapter="${2:-caddyguardfile}"
    stop_test_caddy
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
}

run_bench() {
    local label="$1"
    local extra_args="$2"
    echo "--- $label: ${REQUESTS} req, c=${CONCURRENCY} ---"
    ab -n $REQUESTS -c $CONCURRENCY -H "$UA" $extra_args $TARGET 2>&1
}

# ==========================================
echo "######## 场景 A: Caddy + reverse_proxy（无 WAF 基准） ########"
start_test "$CONF_DIR/Caddyfile.A" caddyfile
RESULT=$(run_bench "A" "")
RPS=$(echo "$RESULT" | grep "Requests per second" | awk '{print $4}')
TPR=$(echo "$RESULT" | grep "Time per request.*mean\b" | head -1 | awk '{print $4}')
FAIL=$(echo "$RESULT" | grep "Failed requests" | awk '{print $3}')
P99=$(echo "$RESULT" | grep "99%" | awk '{print $2}')
echo "A: Caddy+rp: RPS=$RPS TPR=${TPR}ms Failed=$FAIL P99=${P99}ms"
echo "A: Caddy+rp: RPS=$RPS TPR=${TPR}ms Failed=$FAIL P99=${P99}ms" >> $RESULT_FILE

# ==========================================
echo ""
echo "######## 场景 B: CaddyGuard 规则全关 ########"
cat > /tmp/config_B.json << 'EOF'
{"waf_enable":"off","trust_proxy_headers":"on","log_dir":"/tmp","white_url_check":"off","white_ip_check":"off","white_ua_check":"off","black_ip_check":"off","url_check":"off","url_args_check":"off","user_agent_check":"off","cookie_check":"off","cc_check":"off","cc_rate":"999999/60","cc_block_ttl":0,"post_check":"off","referer_check":"off","file_upload_check":"off","waf_output":"html","waf_redirect_url":""}
EOF
deploy_config "/tmp/config_B.json"
start_test "$CONF_DIR/Caddyfile.WAF"
RESULT=$(run_bench "B" "")
RPS=$(echo "$RESULT" | grep "Requests per second" | awk '{print $4}')
TPR=$(echo "$RESULT" | grep "Time per request.*mean\b" | head -1 | awk '{print $4}')
FAIL=$(echo "$RESULT" | grep "Failed requests" | awk '{print $3}')
P99=$(echo "$RESULT" | grep "99%" | awk '{print $2}')
echo "B: WAF rules off: RPS=$RPS TPR=${TPR}ms Failed=$FAIL P99=${P99}ms"
echo "B: WAF rules off: RPS=$RPS TPR=${TPR}ms Failed=$FAIL P99=${P99}ms" >> $RESULT_FILE

# ==========================================
echo ""
echo "######## 场景 C: CaddyGuard 规则全开（不含CC） ########"
cat > /tmp/config_C.json << 'EOF'
{"waf_enable":"on","trust_proxy_headers":"on","log_dir":"/tmp","white_url_check":"on","white_ip_check":"on","white_ua_check":"on","black_ip_check":"on","url_check":"on","url_args_check":"on","user_agent_check":"on","cookie_check":"on","cc_check":"off","cc_rate":"999999/60","cc_block_ttl":0,"post_check":"on","referer_check":"off","file_upload_check":"on","waf_output":"html","waf_redirect_url":""}
EOF
deploy_config "/tmp/config_C.json"
start_test "$CONF_DIR/Caddyfile.WAF"
RESULT=$(run_bench "C" "")
RPS=$(echo "$RESULT" | grep "Requests per second" | awk '{print $4}')
TPR=$(echo "$RESULT" | grep "Time per request.*mean\b" | head -1 | awk '{print $4}')
FAIL=$(echo "$RESULT" | grep "Failed requests" | awk '{print $3}')
P99=$(echo "$RESULT" | grep "99%" | awk '{print $2}')
echo "C: WAF rules on: RPS=$RPS TPR=${TPR}ms Failed=$FAIL P99=${P99}ms"
echo "C: WAF rules on: RPS=$RPS TPR=${TPR}ms Failed=$FAIL P99=${P99}ms" >> $RESULT_FILE

# ==========================================
echo ""
echo "######## 场景 D: CaddyGuard + CC ########"
cat > /tmp/config_D.json << 'EOF'
{"waf_enable":"on","trust_proxy_headers":"on","log_dir":"/tmp","white_url_check":"on","white_ip_check":"on","white_ua_check":"on","black_ip_check":"on","url_check":"on","url_args_check":"on","user_agent_check":"on","cookie_check":"on","cc_check":"on","cc_rate":"999999/60","cc_block_ttl":0,"post_check":"on","referer_check":"off","file_upload_check":"on","waf_output":"html","waf_redirect_url":""}
EOF
deploy_config "/tmp/config_D.json"
start_test "$CONF_DIR/Caddyfile.WAF"
RESULT=$(run_bench "D" "")
RPS=$(echo "$RESULT" | grep "Requests per second" | awk '{print $4}')
TPR=$(echo "$RESULT" | grep "Time per request.*mean\b" | head -1 | awk '{print $4}')
FAIL=$(echo "$RESULT" | grep "Failed requests" | awk '{print $3}')
P99=$(echo "$RESULT" | grep "99%" | awk '{print $2}')
echo "D: WAF+CC: RPS=$RPS TPR=${TPR}ms Failed=$FAIL P99=${P99}ms"
echo "D: WAF+CC: RPS=$RPS TPR=${TPR}ms Failed=$FAIL P99=${P99}ms" >> $RESULT_FILE

# ==========================================
echo ""
echo "######## 场景 E: CaddyGuard + 日志（攻击请求触发日志写入） ########"
cat > /tmp/config_E.json << 'EOF'
{"waf_enable":"on","trust_proxy_headers":"on","log_dir":"/var/log/caddyguard","white_url_check":"on","white_ip_check":"on","white_ua_check":"on","black_ip_check":"on","url_check":"on","url_args_check":"on","user_agent_check":"on","cookie_check":"on","cc_check":"off","cc_rate":"999999/60","cc_block_ttl":0,"post_check":"on","referer_check":"off","file_upload_check":"on","waf_output":"html","waf_redirect_url":""}
EOF
deploy_config "/tmp/config_E.json"
start_test "$CONF_DIR/Caddyfile.WAF"
# 用攻击 UA 触发 WAF 拦截 + 日志写入
echo "--- E: attack UA (sqlmap) triggering WAF log writes ---"
ab -n $REQUESTS -c $CONCURRENCY -H "User-Agent: sqlmap/1.0" $TARGET 2>&1 > /tmp/ab_E.txt
RPS=$(grep "Requests per second" /tmp/ab_E.txt | awk '{print $4}')
TPR=$(grep "Time per request.*mean\b" /tmp/ab_E.txt | head -1 | awk '{print $4}')
FAIL=$(grep "Failed requests" /tmp/ab_E.txt | awk '{print $3}')
P99=$(grep "99%" /tmp/ab_E.txt | awk '{print $2}')
echo "E: WAF+log(attack): RPS=$RPS TPR=${TPR}ms Failed=$FAIL P99=${P99}ms"
echo "E: WAF+log(attack): RPS=$RPS TPR=${TPR}ms Failed=$FAIL P99=${P99}ms" >> $RESULT_FILE
LOG_COUNT=$(cat /var/log/caddyguard/*_waf.log 2>/dev/null | wc -l)
echo "  WAF log entries: $LOG_COUNT" >> $RESULT_FILE

# ==========================================
echo ""
echo "######## 场景 F: CaddyGuard + POST body ########"
deploy_config "/tmp/config_C.json"
start_test "$CONF_DIR/Caddyfile.WAF"
echo "test=hello_world_data_padding_padding_padding" > /tmp/post_data.txt
echo "--- F: POST with body ---"
ab -n $REQUESTS -c $CONCURRENCY -H "$UA" -p /tmp/post_data.txt $TARGET 2>&1 > /tmp/ab_F.txt
RPS=$(grep "Requests per second" /tmp/ab_F.txt | awk '{print $4}')
TPR=$(grep "Time per request.*mean\b" /tmp/ab_F.txt | head -1 | awk '{print $4}')
FAIL=$(grep "Failed requests" /tmp/ab_F.txt | awk '{print $3}')
P99=$(grep "99%" /tmp/ab_F.txt | awk '{print $2}')
echo "F: WAF+POST: RPS=$RPS TPR=${TPR}ms Failed=$FAIL P99=${P99}ms"
echo "F: WAF+POST: RPS=$RPS TPR=${TPR}ms Failed=$FAIL P99=${P99}ms" >> $RESULT_FILE

# ==========================================
echo ""
echo "========================================"
echo "        压测结果汇总 (物理机 180)"
echo "========================================"
cat $RESULT_FILE
echo "========================================"

stop_test_caddy
# 也关闭 backend
pids=$(ss -tlnp | grep ':8080 ' | grep -oP 'pid=\K[0-9]+' | sort -u)
if [ -n "$pids" ]; then
    echo "$pids" | xargs kill 2>/dev/null
fi
echo "All done!"
