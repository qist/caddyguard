#!/bin/bash
# 启动 caddy
mkdir -p /var/log/caddyguard
/opt/caddy-binaries/caddy run --config /opt/caddyguard/test-config/Caddyfile --adapter caddyfile &
CADDY_PID=$!
sleep 3

echo "=== 正常请求 ==="
curl -s -o /dev/null -w "HTTP %{http_code}\n" http://localhost:8888/

echo "=== SQL注入 URL 参数测试 ==="
curl -s -o /dev/null -w "HTTP %{http_code}\n" "http://localhost:8888/?id=1+union+select+1"

echo "=== 路径遍历测试 ==="
curl -s -o /dev/null -w "HTTP %{http_code}\n" "http://localhost:8888/../etc/passwd"

echo "=== 扫描器 UA 测试 ==="
curl -s -o /dev/null -w "HTTP %{http_code}\n" -A "sqlmap/1.0" http://localhost:8888/

echo "=== XSS 测试 ==="
curl -s -o /dev/null -w "HTTP %{http_code}\n" "http://localhost:8888/?q=<script>alert(1)</script>"

echo "=== POST 注入测试 ==="
curl -s -o /dev/null -w "HTTP %{http_code}\n" -d "id=1 union select 1,2,3" http://localhost:8888/

echo "=== Cookie 注入测试 ==="
curl -s -o /dev/null -w "HTTP %{http_code}\n" -b "session=union select from" http://localhost:8888/

echo "=== 正常请求（应放行）==="
curl -s http://localhost:8888/
echo ""

# 停止 caddy
kill $CADDY_PID 2>/dev/null
wait $CADDY_PID 2>/dev/null
