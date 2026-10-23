#!/bin/bash
# CaddyGuard cc_mode 计数粒度回归测试
# 参考 nginxguard/test/waf_regression_test.sh 第 10 节用例
# 在 180 本地执行（也可 CADDY=... 指定测试二进制）
#
# 设计决策（与 Lua 端一致，见 nginxguard README「CC 封禁隔离设计说明」）:
#   1. 计数/拉黑 key 粒度跟随 cc_mode:
#      ip(默认)  => 计数 cc:<IP>,          拉黑 <IP>            (全局)
#      ip_uri    => 计数 cc:<IP>|<URI>,    拉黑 <IP>            (全局)
#      ip_host   => 计数 cc:h|<域名>|<IP>, 拉黑 h|<域名>|<IP>   (仅该域名)
#   2. 隔离是单向的: ip_host 域名自身触发只封域名级; 其他域名触发的全局封禁
#      对所有域名无条件生效 (安全兜底)
#   3. cc_block_ttl=0 逃生门: 该域名不自动拉黑, 也不检查任何 CC 封禁

CADDY="${CADDY:-/opt/caddyguard/caddy}"
CONF_DIR="/opt/caddyguard/test-config"
RULE_DIR="/opt/caddyguard/rule-config"
TARGET="http://127.0.0.1:8888"
PASS=0
FAIL=0
ERRORS=""

# 备份原始配置, 退出时恢复
cp -f $RULE_DIR/config.json /tmp/cc_mode_config.json.bak 2>/dev/null
if [ -f $RULE_DIR/domain.json ]; then
    cp -f $RULE_DIR/domain.json /tmp/cc_mode_domain.json.bak
fi
restore_cfg() {
    cp -f /tmp/cc_mode_config.json.bak $RULE_DIR/config.json 2>/dev/null
    if [ -f /tmp/cc_mode_domain.json.bak ]; then
        cp -f /tmp/cc_mode_domain.json.bak $RULE_DIR/domain.json
    elif [ -f $RULE_DIR/domain.json ]; then
        rm -f $RULE_DIR/domain.json
    fi
}
trap restore_cfg EXIT

# 写 config.json: $1=cc_mode $2=cc_block_ttl
set_config() {
    cat > $RULE_DIR/config.json << EOF
{"waf_enable":"on","trust_proxy_headers":"on","log_dir":"/tmp","white_url_check":"on","white_ip_check":"on","white_ua_check":"on","black_ip_check":"on","url_check":"on","url_args_check":"on","user_agent_check":"on","header_check":"on","cookie_check":"on","cc_check":"on","cc_mode":"$1","cc_rate":"10/60","cc_block_ttl":$2,"post_check":"on","referer_check":"off","file_upload_check":"on","waf_output":"html"}
EOF
}

# 写 domain.json (域名级 cc_mode 覆盖用例)
set_domain() {
    cat > $RULE_DIR/domain.json << EOF
{"h1.ccmode.test":{"cc_mode":"ip_host","cc_rate":"10/60","cc_block_ttl":300}}
EOF
}

start_backend() {
    nohup $CADDY run --config $CONF_DIR/Caddyfile.backend --adapter caddyfile > /tmp/caddy_backend.log 2>&1 &
    sleep 1
}

# 杀掉所有 WAF caddy（按完整命令行匹配, 不依赖二进制文件名）
# 注意: caddy 2.10+ 监听使用 SO_REUSEPORT, 杀不干净时新进程也能绑定成功
kill_waf() {
    kill $(pgrep -f "run --config $CONF_DIR/Caddyfile.WAF") 2>/dev/null || true
    for i in $(seq 1 25); do
        pgrep -f "run --config $CONF_DIR/Caddyfile.WAF" > /dev/null || return 0
        sleep 0.2
    done
    echo "FATAL: WAF caddy 进程未被杀掉"
    exit 1
}

# 重启 WAF caddy: 清空内存计数/封禁状态 + 加载最新配置
restart_waf() {
    kill_waf
    nohup $CADDY run --config $CONF_DIR/Caddyfile.WAF --adapter caddyguardfile > /tmp/caddy_waf.log 2>&1 &
    # 等待端口就绪(任意状态码都算服务起来)
    for i in $(seq 1 10); do
        code=$(curl -s -m 2 -o /dev/null -w "%{http_code}" -H "User-Agent: Mozilla/5.0" "$TARGET/" 2>/dev/null)
        [ "$code" != "000" ] && break
        sleep 1
    done
    # SO_REUSEPORT 下多进程都能绑定成功, 必须校验只有一个 WAF 进程
    n=$(pgrep -fc "run --config $CONF_DIR/Caddyfile.WAF")
    if [ "$n" != "1" ]; then
        echo "FATAL: 期望 1 个 WAF 进程, 实际 $n 个"
        exit 1
    fi
}

# cc_burst <count> <path> [host] : 发 n 个请求, 输出最后一个状态码
cc_burst() {
    local n="$1" p="$2" h="$3" code=""
    for i in $(seq 1 "$n"); do
        if [ -n "$h" ]; then
            code=$(curl --globoff -s -m 3 -o /dev/null -w "%{http_code}" -H "User-Agent: Mozilla/5.0" -H "Host: $h" "$TARGET$p")
        else
            code=$(curl --globoff -s -m 3 -o /dev/null -w "%{http_code}" -H "User-Agent: Mozilla/5.0" "$TARGET$p")
        fi
    done
    echo "$code"
}

ok() {
    echo "  PASS  $1  (HTTP $2)"
    PASS=$((PASS+1))
}
bad() {
    echo "  FAIL  $1  (got $2, want $3)"
    FAIL=$((FAIL+1))
    ERRORS="$ERRORS\n  $1: got $2, want $3"
}
expect() { # $1=名称 $2=期望 $3=实际
    if [ "$3" = "$2" ]; then ok "$1" "$3"; else bad "$1" "$3" "$2"; fi
}
expect_not() { # $1=名称 $2=不期望 $3=实际
    if [ "$3" != "$2" ]; then ok "$1" "$3"; else bad "$1" "$3" "非$2"; fi
}

echo "========================================"
echo "  CaddyGuard cc_mode 回归测试"
echo "  二进制: $CADDY"
echo "  $(date '+%Y-%m-%d %H:%M:%S')"
echo "========================================"

# 启动
# 按完整命令行杀掉所有旧 caddy(含 caddy-ccmode 等自定义命名的二进制)
kill $(pgrep -x caddy) 2>/dev/null || true
kill $(pgrep -f "run --config $CONF_DIR/Caddyfile.WAF") 2>/dev/null || true
kill $(pgrep -f "run --config $CONF_DIR/Caddyfile.backend") 2>/dev/null || true
for i in $(seq 1 25); do
    pgrep -f "Caddyfile.WAF|Caddyfile.backend" > /dev/null || break
    sleep 0.2
done
start_backend
set_config "ip" 0
restart_waf

code=$(curl -s -m 5 -o /dev/null -w "%{http_code}" -H "User-Agent: Mozilla/5.0" $TARGET/)
if [ "$code" != "200" ]; then
    echo "FATAL: Caddy failed to start, HTTP $code"
    tail -20 /tmp/caddy_waf.log
    exit 1
fi
echo "Caddy started OK (HTTP 200)"

# ============================================================
# 10.1 cc_mode=ip (默认): 跨 URI 共享额度
# ============================================================
echo ""
echo "--- 10.1 cc_mode=ip: 跨 URI 共享 ---"
restart_waf
cc_burst 6 /ccm-a > /dev/null
cc_burst 6 /ccm-b > /dev/null
code=$(cc_burst 1 /ccm-a)
expect "ip模式: 两个URI合计12次超过10/60触发" 403 "$code"

# ============================================================
# 10.2 cc_mode=ip_uri: URI 独立计数
# ============================================================
echo "--- 10.2 cc_mode=ip_uri: URI 独立 ---"
set_config "ip_uri" 0
restart_waf
cc_burst 6 /ccm-a > /dev/null
code=$(cc_burst 6 /ccm-b)
expect_not "ip_uri模式: 两个URI各6次不触发" 403 "$code"
code=$(cc_burst 12 /ccm-c)
expect "ip_uri模式: 单URI 12次超过10/60触发" 403 "$code"

# ============================================================
# 10.3 cc_mode=ip_host: 域名独立计数 + 封禁隔离
# ============================================================
echo "--- 10.3 cc_mode=ip_host: 域名独立 ---"
set_config "ip_host" 300
restart_waf
cc_burst 6 /ccm-h h1.ccmode.test > /dev/null
code=$(cc_burst 6 /ccm-h h2.ccmode.test)
expect_not "ip_host模式: 两个域名各6次不触发" 403 "$code"
code=$(cc_burst 12 /ccm-h h1.ccmode.test)
expect "ip_host模式: 单域名12次超过10/60触发" 403 "$code"
code=$(curl --globoff -s -m 3 -o /dev/null -w "%{http_code}" -H "User-Agent: Mozilla/5.0" -H "Host: h2.ccmode.test" "$TARGET/ccm-h")
expect_not "ip_host模式: h1被封后h2不受影响(封禁隔离)" 403 "$code"
code=$(curl --globoff -s -m 3 -o /dev/null -w "%{http_code}" -H "User-Agent: Mozilla/5.0" "$TARGET/ccm-h")
expect_not "ip_host模式: h1被封后默认域名不受影响(域名级封禁不泄漏全局)" 403 "$code"

# ============================================================
# 10.4 设计决策: 全局封禁对所有域名无条件生效 (单向隔离)
#     ip 模式触发 => 封整个 IP => ip_host 语义的域名也被 403
# ============================================================
echo "--- 10.4 全局封禁跨域名兜底 (设计决策) ---"
set_config "ip" 300
restart_waf
cc_burst 12 /ccm-g > /dev/null
code=$(curl --globoff -s -m 3 -o /dev/null -w "%{http_code}" -H "User-Agent: Mozilla/5.0" "$TARGET/")
expect "ip模式: 默认域名12次触发后本域名403" 403 "$code"
code=$(curl --globoff -s -m 3 -o /dev/null -w "%{http_code}" -H "User-Agent: Mozilla/5.0" -H "Host: h1.ccmode.test" "$TARGET/ccm-h")
expect "设计决策: 全局封禁下其他域名同样403(无条件生效)" 403 "$code"

# ============================================================
# 10.5 domain.json 域名级 cc_mode 覆盖
#     全局 ip 模式 + cc_block_ttl=0; h1 覆盖为 ip_host + ttl=300
#     h1 触发只封 h1, h2 走全局计数不受影响
# ============================================================
echo "--- 10.5 domain.json 域名级 cc_mode 覆盖 ---"
set_config "ip" 0
set_domain
restart_waf
code=$(cc_burst 12 /ccm-d h1.ccmode.test)
expect "域名覆盖: h1(ip_host) 12次触发403" 403 "$code"
code=$(curl --globoff -s -m 3 -o /dev/null -w "%{http_code}" -H "User-Agent: Mozilla/5.0" -H "Host: h2.ccmode.test" "$TARGET/ccm-d")
expect_not "域名覆盖: h1被封后h2走全局配置不受影响" 403 "$code"

# ============================================================
# 清理: 恢复配置 (trap EXIT 已处理)
# ============================================================
kill $(pgrep -x caddy) 2>/dev/null || true
kill $(pgrep -f "run --config $CONF_DIR/Caddyfile.WAF") 2>/dev/null || true
kill $(pgrep -f "run --config $CONF_DIR/Caddyfile.backend") 2>/dev/null || true

echo ""
echo "========================================"
echo "  测试结果汇总"
echo "  PASS: $PASS  FAIL: $FAIL"
echo "========================================"
if [ $FAIL -gt 0 ]; then
    echo -e "失败项:$ERRORS"
fi
echo "配置已恢复, WAF caddy 已停止"
echo "Done!"
