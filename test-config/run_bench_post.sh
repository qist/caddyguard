#!/bin/bash
# POST body 优化对比压测 - 只跑关键场景
set -e

CADDY="/opt/caddyguard/caddy"
CONF_DIR="/opt/caddyguard/test-config"
RULE_DIR="/opt/caddyguard/rule-config"
LOG_FILE="/tmp/caddy_bench.log"
TARGET="http://127.0.0.1:8888/"
REQUESTS=50000
CONCURRENCY=200
UA="User-Agent: Mozilla/5.0"
RESULT_FILE="/tmp/bench_post_opt.txt"
> $RESULT_FILE

stop_caddy() {
    kill $(pgrep caddy) 2>/dev/null || true
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

parse_result() {
    local ab_file="$1"
    local label="$2"
    RPS=$(grep "Requests per second" "$ab_file" | awk '{print $4}')
    TPR=$(grep "Time per request.*mean\b" "$ab_file" | head -1 | awk '{print $4}')
    FAIL=$(grep "Failed requests" "$ab_file" | awk '{print $3}')
    P99=$(grep "99%" "$ab_file" | awk '{print $2}')
    echo "$label: RPS=$RPS TPR=${TPR}ms Failed=$FAIL P99=${P99}ms"
    echo "$label: RPS=$RPS TPR=${TPR}ms Failed=$Fail P99=${P99}ms" >> $RESULT_FILE
}

echo "========================================"
echo "  POST body 优化对比压测"
echo "  $(date '+%Y-%m-%d %H:%M:%S')"
echo "  Requests=$REQUESTS Concurrency=$CONCURRENCY"
echo "========================================"
echo ""

# POST data
echo "test=hello_world_data_padding_padding_padding" > /tmp/post_data.txt

# 场景 A: 无 WAF 基准
echo "######## A: 无 WAF 基准 ########"
start_test "$CONF_DIR/Caddyfile.A" caddyfile
ab -n $REQUESTS -c $CONCURRENCY -H "$UA" $TARGET > /tmp/ab_A.txt 2>&1
parse_result /tmp/ab_A.txt "A: NoWAF" $RESULT_FILE

# 场景 C: WAF 全开(不含CC) GET 请求
echo ""
echo "######## C: WAF 全开 GET ########"
cat > /tmp/config_C.json << 'EOF'
{"waf_enable":"on","trust_proxy_headers":"on","log_dir":"/tmp","white_url_check":"on","white_ip_check":"on","white_ua_check":"on","black_ip_check":"on","url_check":"on","url_args_check":"on","user_agent_check":"on","cookie_check":"on","cc_check":"off","cc_rate":"999999/60","cc_block_ttl":0,"post_check":"on","referer_check":"off","file_upload_check":"on","waf_output":"html","waf_redirect_url":""}
EOF
deploy_config "/tmp/config_C.json"
start_test "$CONF_DIR/Caddyfile.WAF"
ab -n $REQUESTS -c $CONCURRENCY -H "$UA" $TARGET > /tmp/ab_C.txt 2>&1
parse_result /tmp/ab_C.txt "C: WAF-on-GET" $RESULT_FILE

# 场景 F: WAF 全开 + POST body
echo ""
echo "######## F: WAF 全开 + POST body ########"
ab -n $REQUESTS -c $CONCURRENCY -H "$UA" -p /tmp/post_data.txt $TARGET > /tmp/ab_F.txt 2>&1
parse_result /tmp/ab_F.txt "F: WAF+POST" $RESULT_FILE

# 场景 O: 仅 POST body 检测
echo ""
echo "######## O: 仅 POST body 检测 ########"
cat > /tmp/config_O.json << 'EOF'
{"waf_enable":"on","trust_proxy_headers":"on","log_dir":"/tmp","white_url_check":"off","white_ip_check":"off","white_ua_check":"off","black_ip_check":"off","url_check":"off","url_args_check":"off","user_agent_check":"off","cookie_check":"off","cc_check":"off","cc_rate":"999999/60","cc_block_ttl":0,"post_check":"on","referer_check":"off","file_upload_check":"off","waf_output":"html","waf_redirect_url":""}
EOF
deploy_config "/tmp/config_O.json"
start_test "$CONF_DIR/Caddyfile.WAF"
ab -n $REQUESTS -c $CONCURRENCY -H "$UA" -p /tmp/post_data.txt $TARGET > /tmp/ab_O.txt 2>&1
parse_result /tmp/ab_O.txt "O: POST-only" $RESULT_FILE

# 场景 F2: WAF 全开(不含POST) + POST body 对比
echo ""
echo "######## F2: WAF 全开(POST off) + POST body ########"
cat > /tmp/config_F2.json << 'EOF'
{"waf_enable":"on","trust_proxy_headers":"on","log_dir":"/tmp","white_url_check":"on","white_ip_check":"on","white_ua_check":"on","black_ip_check":"on","url_check":"on","url_args_check":"on","user_agent_check":"on","cookie_check":"on","cc_check":"off","cc_rate":"999999/60","cc_block_ttl":0,"post_check":"off","referer_check":"off","file_upload_check":"on","waf_output":"html","waf_redirect_url":""}
EOF
deploy_config "/tmp/config_F2.json"
start_test "$CONF_DIR/Caddyfile.WAF"
ab -n $REQUESTS -c $CONCURRENCY -H "$UA" -p /tmp/post_data.txt $TARGET > /tmp/ab_F2.txt 2>&1
parse_result /tmp/ab_F2.txt "F2: WAF-noPOST+body" $RESULT_FILE

# 场景 M: multipart POST (会被 postAttackCheck 跳过)
echo ""
echo "######## M: multipart POST (POST check 跳过) ########"
deploy_config "/tmp/config_C.json"
start_test "$CONF_DIR/Caddyfile.WAF"
# 创建 multipart data
echo -e '--boundary\r\nContent-Disposition: form-data; name="field1"\r\n\r\ntest_value\r\n--boundary--' > /tmp/multipart_data.txt
ab -n $REQUESTS -c $CONCURRENCY -H "$UA" -H "Content-Type: multipart/form-data; boundary=boundary" -p /tmp/multipart_data.txt $TARGET > /tmp/ab_M.txt 2>&1
parse_result /tmp/ab_M.txt "M: multipart-POST" $RESULT_FILE

# 汇总
echo ""
echo "========================================"
echo "        POST 优化对比压测结果"
echo "        $(date '+%Y-%m-%d %H:%M:%S')"
echo "========================================"
cat $RESULT_FILE
echo "========================================"

stop_caddy
echo "All done!"
