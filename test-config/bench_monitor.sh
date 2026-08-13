#!/bin/bash
# 压测 + CPU/RSS 监控 v2
# 简化版：ab 压测前启动 pidstat，压测后停止
CADDY="/opt/caddyguard/caddy"
CONF_DIR="/opt/caddyguard/test-config"
RULE_DIR="/opt/caddyguard/rule-config"
REQUESTS=50000
CONC=200
UA="User-Agent: Mozilla/5.0"
RESULT="/tmp/bench_v2.txt"
> $RESULT

stop_caddy() { pkill caddy 2>/dev/null; sleep 1; }
get_waf_pid() { pgrep -f "Caddyfile.WAF" | head -1; }

run_scene() {
    local label="$1"
    local caddyfile="$2"
    local config="$3"
    local extra="$4"

    stop_caddy
    # 启动后端
    nohup $CADDY run --config $CONF_DIR/Caddyfile.backend --adapter caddyfile > /tmp/caddy_backend.log 2>&1 &
    sleep 1
    # 部署配置
    if [ -n "$config" ]; then cp "$config" $RULE_DIR/config.json; sleep 3; fi
    # 启动 WAF
    nohup $CADDY run --config "$caddyfile" --adapter caddyfile > /tmp/caddy_waf.log 2>&1 &
    sleep 2

    # 验证
    code=$(curl -s -m 3 -o /dev/null -w "%{http_code}" -H "$UA" http://127.0.0.1:8888/)
    if [ "$code" != "200" ]; then
        echo "$label: ERROR caddy not ready (HTTP $code)"
        return
    fi

    PID=$(get_waf_pid)
    # 启动 pidstat 采样（每 1 秒，后台运行）
    pidstat -u -r -h -p $PID 1 60 > /tmp/pidstat_${label}.txt 2>/dev/null &
    PIDSTAT_PID=$!
    sleep 1

    # 压测
    ab -n $REQUESTS -c $CONC -H "$UA" $extra http://127.0.0.1:8888/ > /tmp/ab_${label}.txt 2>&1

    sleep 1
    kill $PIDSTAT_PID 2>/dev/null
    wait $PIDSTAT_PID 2>/dev/null

    # 分析
    RPS=$(grep "Requests per second" /tmp/ab_${label}.txt | awk '{print $4}')
    P99=$(grep "99%" /tmp/ab_${label}.txt | awk '{print $2}')
    # CPU 平均值（从 pidstat 取 %CPU 列的平均值）
    AVG_CPU=$(awk '/Average/ {print $8}' /tmp/pidstat_${label}.txt 2>/dev/null | awk '{s+=$1;n++} END{if(n>0) printf "%.1f", s/n; else print "?"}')
    # 如果 pidstat 没有 Average 行，手动算
    if [ -z "$AVG_CPU" ] || [ "$AVG_CPU" = "?" ]; then
        AVG_CPU=$(awk 'NR>3 && $8 ~ /^[0-9]/ {s+=$8; n++} END{if(n>0) printf "%.1f", s/n; else print "?"}' /tmp/pidstat_${label}.txt 2>/dev/null)
    fi
    # RSS 峰值（KB）
    PEAK_RSS=$(awk 'NR>3 && $10 ~ /^[0-9]/ {if($10>m) m=$10} END{print m}' /tmp/pidstat_${label}.txt 2>/dev/null)
    if [ -z "$PEAK_RSS" ]; then
        # fallback: 用 ps 采样
        PEAK_RSS=$(awk '{if($2>m) m=$2} END{print m}' /tmp/pidstat_${label}.txt 2>/dev/null)
    fi

    echo "$label: RPS=$RPS CPU=${AVG_CPU}% RSS=${PEAK_RSS}KB P99=${P99}ms" | tee -a $RESULT
}

echo "======== CaddyGuard 压测+监控 ========" | tee -a $RESULT

# A: Caddy + reverse_proxy
run_scene "A" "$CONF_DIR/Caddyfile.A" "" ""

# B: WAF off
cat > /tmp/config_B.json << 'EOF'
{"waf_enable":"off","trust_proxy_headers":"on","log_dir":"/tmp","white_url_check":"off","white_ip_check":"off","white_ua_check":"off","black_ip_check":"off","url_check":"off","url_args_check":"off","user_agent_check":"off","cookie_check":"off","cc_check":"off","cc_rate":"999999/60","cc_block_ttl":0,"post_check":"off","referer_check":"off","file_upload_check":"off","waf_output":"html","waf_redirect_url":""}
EOF
run_scene "B" "$CONF_DIR/Caddyfile.WAF" "/tmp/config_B.json" ""

# C: WAF on
cat > /tmp/config_C.json << 'EOF'
{"waf_enable":"on","trust_proxy_headers":"on","log_dir":"/tmp","white_url_check":"on","white_ip_check":"on","white_ua_check":"on","black_ip_check":"on","url_check":"on","url_args_check":"on","user_agent_check":"on","cookie_check":"on","cc_check":"off","cc_rate":"999999/60","cc_block_ttl":0,"post_check":"on","referer_check":"off","file_upload_check":"on","waf_output":"html","waf_redirect_url":""}
EOF
run_scene "C" "$CONF_DIR/Caddyfile.WAF" "/tmp/config_C.json" ""

# D: WAF + CC
cat > /tmp/config_D.json << 'EOF'
{"waf_enable":"on","trust_proxy_headers":"on","log_dir":"/tmp","white_url_check":"on","white_ip_check":"on","white_ua_check":"on","black_ip_check":"on","url_check":"on","url_args_check":"on","user_agent_check":"on","cookie_check":"on","cc_check":"on","cc_rate":"999999/60","cc_block_ttl":0,"post_check":"on","referer_check":"off","file_upload_check":"on","waf_output":"html","waf_redirect_url":""}
EOF
run_scene "D" "$CONF_DIR/Caddyfile.WAF" "/tmp/config_D.json" ""

# F: WAF + POST
echo "test=hello_world_padding" > /tmp/post_data.txt
run_scene "F" "$CONF_DIR/Caddyfile.WAF" "/tmp/config_C.json" "-p /tmp/post_data.txt"

echo "" | tee -a $RESULT
echo "======== 汇总 ========" | tee -a $RESULT
cat $RESULT

stop_caddy
echo "Done!"
