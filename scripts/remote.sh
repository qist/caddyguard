#!/bin/bash
# caddyguard 远程部署与管理脚本
# 用法: ./remote.sh [deploy|start|stop|restart|status|logs|waflogs|test]
set -e

REMOTE="192.168.2.186"
REMOTE_DIR="/opt/caddyguard"
CADDY_BIN="/opt/caddy-binaries/caddy"
CADDYFILE="${REMOTE_DIR}/test-config/Caddyfile"
LOG_FILE="/tmp/caddy_remote.log"
WAF_LOG_DIR="/var/log/caddyguard"

# 本地路径 (WSL2)
LOCAL_DIR="/opt/caddyguard"

ssh_cmd() {
    ssh -o ConnectTimeout=10 -o ServerAliveInterval=5 "$REMOTE" "$1"
}

case "${1:-deploy}" in

deploy)
    echo ">>> 1. 复制 caddy 二进制..."
    ssh_cmd "mkdir -p ${REMOTE_DIR}/rule-config ${REMOTE_DIR}/test-config ${CADDY_BIN%/*} ${WAF_LOG_DIR}"
    scp "${LOCAL_DIR}/../caddy-binaries/caddy" "${REMOTE}:${CADDY_BIN}" 2>/dev/null || \
        scp "/opt/caddy-binaries/caddy" "${REMOTE}:${CADDY_BIN}"
    ssh_cmd "chmod +x ${CADDY_BIN}"

    echo ">>> 2. 复制规则配置..."
    scp -r "${LOCAL_DIR}/rule-config/"* "${REMOTE}:${REMOTE_DIR}/rule-config/"

    echo ">>> 3. 复制证书..."
    ssh_cmd "rm -rf ${REMOTE_DIR}/certs"
    scp -r /opt/corefusion/data/certs/gg "${REMOTE}:${REMOTE_DIR}/certs"

    echo ">>> 4. 复制 Caddyfile..."
    scp "${LOCAL_DIR}/test-config/Caddyfile.remote" "${REMOTE}:${CADDYFILE}"

    echo ">>> 部署完成!"
    ;;

start)
    echo ">>> 启动 caddy..."
    ssh_cmd "nohup ${CADDY_BIN} run --config ${CADDYFILE} --adapter caddyfile > ${LOG_FILE} 2>&1 & echo PID=\$!"
    sleep 2
    ssh_cmd "ss -tlnp | grep -E ':443 |:8443 ' || echo 'WARNING: 端口未监听'"
    ;;

stop)
    echo ">>> 停止 caddy..."
    ssh_cmd "pkill -f 'caddy run' 2>/dev/null || echo 'caddy 未运行'"
    ;;

restart)
    $0 stop
    sleep 1
    $0 start
    ;;

status)
    ssh_cmd "ps aux | grep 'caddy run' | grep -v grep || echo 'caddy 未运行'; echo '---'; ss -tlnp | grep -E ':443 |:8443 ' 2>/dev/null || echo '端口未监听'"
    ;;

logs)
    ssh_cmd "tail -50 ${LOG_FILE}"
    ;;

waflogs)
    ssh_cmd "cat ${WAF_LOG_DIR}/\$(date +%Y-%m-%d)_waf.log 2>/dev/null || echo '无 WAF 日志'"
    ;;

clearlogs)
    ssh_cmd "rm -f ${WAF_LOG_DIR}/*_waf.log; truncate -s 0 ${LOG_FILE} 2>/dev/null; echo '日志已清空'"
    ;;

test)
    echo "=========================================="
    echo "  caddyguard 真实 IP 传递测试"
    echo "=========================================="
    echo ""

    # 清空日志
    ssh_cmd "rm -f ${WAF_LOG_DIR}/*_waf.log; truncate -s 0 ${LOG_FILE} 2>/dev/null"

    echo ">>> 测试1: 正常请求 (期望 200, 后端返回真实IP)"
    RESP=$(curl -sk -w "\n%{http_code}" "https://waf.wyfc.qzz.io/" 2>&1)
    HTTP_CODE=$(echo "$RESP" | tail -1)
    BODY=$(echo "$RESP" | head -n -1)
    echo "  HTTP: $HTTP_CODE"
    echo "  后端响应: $BODY" | head -5
    echo ""

    echo ">>> 测试2: SQL注入 (期望 403 WAF拦截)"
    curl -sk -o /dev/null -w "  HTTP: %{http_code}\n" "https://waf.wyfc.qzz.io/?id=1+union+select+1"
    echo ""

    echo ">>> 测试3: XSS (期望 403 WAF拦截)"
    curl -sk -o /dev/null -w "  HTTP: %{http_code}\n" "https://waf.wyfc.qzz.io/?q=<script>alert(1)</script>"
    echo ""

    echo ">>> 测试4: 恶意UA (期望 403 WAF拦截)"
    curl -sk -o /dev/null -w "  HTTP: %{http_code}\n" -A "sqlmap/1.0" "https://waf.wyfc.qzz.io/"
    echo ""

    echo ">>> 测试5: 模拟X-Forwarded-For伪造"
    curl -sk -o /dev/null -w "  HTTP: %{http_code}\n" -H "X-Forwarded-For: 9.9.9.9" "https://waf.wyfc.qzz.io/"
    echo ""

    sleep 1
    echo "=========================================="
    echo "  Caddy Access Log (remote_ip)"
    echo "=========================================="
    ssh_cmd "grep 'handled request' ${LOG_FILE} 2>/dev/null | python3 -c \"
import sys, json
for l in sys.stdin:
    l = l.strip()
    if not l: continue
    try:
        d = json.loads(l)
        r = d['request']
        print('  remote_ip=%s  client_ip=%s  uri=%s  status=%s' % (
            r.get('remote_ip','?'), r.get('client_ip','?'),
            r.get('uri','?')[:50], d.get('status','?')))
    except: pass
\" 2>/dev/null || echo '  无日志'"

    echo ""
    echo "=========================================="
    echo "  WAF Log (client_ip)"
    echo "=========================================="
    ssh_cmd "cat ${WAF_LOG_DIR}/\$(date +%Y-%m-%d)_waf.log 2>/dev/null | python3 -c \"
import sys, json
for l in sys.stdin:
    l = l.strip()
    if not l: continue
    try:
        d = json.loads(l)
        print('  client_ip=%s  method=%s  url=%s' % (
            d.get('client_ip','?'), d.get('attack_method','?'),
            d.get('req_url','?')[:50]))
    except: pass
\" 2>/dev/null || echo '  无 WAF 日志'"
    echo ""
    echo "=========================================="
    echo "  本机出口IP"
    echo "=========================================="
    echo "  $(ip route get 192.168.2.186 2>/dev/null | grep -oP 'src \K[0-9.]+')"
    echo ""
    ;;

*)
    echo "用法: $0 {deploy|start|stop|restart|status|logs|waflogs|clearlogs|test}"
    exit 1
    ;;
esac
