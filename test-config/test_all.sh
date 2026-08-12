#!/bin/bash
# 完整 WAF 测试：包括 CC 攻击、文件上传等
mkdir -p /var/log/caddyguard
/opt/caddy-binaries/caddy run --config /opt/caddyguard/test-config/Caddyfile --adapter caddyfile &
CADDY_PID=$!
sleep 3

echo "========================================="
echo "1. 正常请求（应放行 200）"
echo "========================================="
curl -s -o /dev/null -w "HTTP %{http_code}\n" http://localhost:8888/

echo ""
echo "========================================="
echo "2. SQL注入 URL 参数（应拦截 403）"
echo "========================================="
curl -s -o /dev/null -w "HTTP %{http_code}\n" "http://localhost:8888/?id=1+union+select+1"

echo ""
echo "========================================="
echo "3. 路径遍历（应拦截 403）"
echo "========================================="
curl -s -o /dev/null -w "HTTP %{http_code}\n" "http://localhost:8888/../etc/passwd"

echo ""
echo "========================================="
echo "4. 扫描器 UA（应拦截 403）"
echo "========================================="
curl -s -o /dev/null -w "HTTP %{http_code}\n" -A "sqlmap/1.0" http://localhost:8888/

echo ""
echo "========================================="
echo "5. XSS（应拦截 403）"
echo "========================================="
curl -s -o /dev/null -w "HTTP %{http_code}\n" "http://localhost:8888/?q=<script>alert(1)</script>"

echo ""
echo "========================================="
echo "6. POST 注入（应拦截 403）"
echo "========================================="
curl -s -o /dev/null -w "HTTP %{http_code}\n" -d "id=1 union select 1,2,3" http://localhost:8888/

echo ""
echo "========================================="
echo "7. Cookie 注入（应拦截 403）"
echo "========================================="
curl -s -o /dev/null -w "HTTP %{http_code}\n" -b "session=union select from" http://localhost:8888/

echo ""
echo "========================================="
echo "8. Referer 检测（应拦截 403）"
echo "========================================="
curl -s -o /dev/null -w "HTTP %{http_code}\n" -e "http://evil.pay.com/steal" http://localhost:8888/

echo ""
echo "========================================="
echo "9. 文件上传黑名单扩展名（应拦截 403）"
echo "========================================="
echo "test" > /tmp/test.sql
curl -s -o /dev/null -w "HTTP %{http_code}\n" -F "file=@/tmp/test.sql" http://localhost:8888/

echo ""
echo "========================================="
echo "10. 黑名单扩展名 .htaccess（应拦截 403）"
echo "========================================="
echo "test" > /tmp/.htaccess
curl -s -o /dev/null -w "HTTP %{http_code}\n" -F "file=@/tmp/.htaccess" http://localhost:8888/

echo ""
echo "========================================="
echo "11. 正常文件上传 .txt（应放行 200）"
echo "========================================="
echo "hello" > /tmp/test.txt
curl -s -o /dev/null -w "HTTP %{http_code}\n" -F "file=@/tmp/test.txt" http://localhost:8888/

echo ""
echo "========================================="
echo "12. CC 攻击测试 - 快速发 130 个请求"
echo "    (cc_rate=120, 超过应触发封禁 403)"
echo "========================================="
BLOCKED=0
PASSED=0
for i in $(seq 1 130); do
  CODE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8888/)
  if [ "$CODE" = "403" ]; then
    BLOCKED=$((BLOCKED+1))
  else
    PASSED=$((PASSED+1))
  fi
done
echo "放行: $PASSED 次, 拦截: $BLOCKED 次"
if [ "$BLOCKED" -gt 0 ]; then
  echo "✅ CC 检测触发"
else
  echo "❌ CC 检测未触发"
fi

echo ""
echo "========================================="
echo "13. CC 封禁后持续访问（应全部 403）"
echo "========================================="
CODE1=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8888/)
CODE2=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8888/)
echo "封禁后请求1: $CODE1"
echo "封禁后请求2: $CODE2"

echo ""
echo "========================================="
echo "14. 白名单 URL（应放行 200）"
echo "========================================="
curl -s -o /dev/null -w "HTTP %{http_code}\n" "http://localhost:8888/123/"

echo ""
echo "========================================="
echo "15. 白名单 IP（8.8.8.8 应放行）"
echo "========================================="
curl -s -o /dev/null -w "HTTP %{http_code}\n" -H "X-Forwarded-For: 8.8.8.8" "http://localhost:8888/?id=union+select"

echo ""
echo "========================================="
echo "16. 黑名单 URL 扩展名 .sql（应拦截 403）"
echo "========================================="
curl -s -o /dev/null -w "HTTP %{http_code}\n" "http://localhost:8888/test.sql"

echo ""
echo "========================================="
echo "检查 WAF 日志"
echo "========================================="
LOGFILE="/var/log/caddyguard/$(date +%Y-%m-%d)_waf.log"
if [ -f "$LOGFILE" ]; then
  echo "日志文件: $LOGFILE"
  echo "日志条数: $(wc -l < $LOGFILE)"
  echo "--- 最后5条日志 ---"
  tail -5 "$LOGFILE" | python3 -m json.tool 2>/dev/null || tail -5 "$LOGFILE"
else
  echo "未找到日志文件"
fi

# 停止 caddy
kill $CADDY_PID 2>/dev/null
wait $CADDY_PID 2>/dev/null
