#!/bin/bash
pkill -f "caddy run" 2>/dev/null
sleep 1
mkdir -p /var/log/caddyguard
rm -f /var/log/caddyguard/*_waf.log

/opt/caddy-binaries/caddy run --config /opt/caddyguard/test-config/Caddyfile --adapter caddyfile 2>/dev/null &
CADDY_PID=$!
sleep 3

# 通过 :443 SNI 转发访问
URL="https://sub.wyfc.qzz.io/7dd7900db90f349a39b13c8a198f4d82ce12d6a8062c89261ada0af8db3820d8"

echo "========================================="
echo "通过 :443 SNI → :8443 WAF → :8081 后端"
echo "========================================="

echo "=== 1. 正常请求 (应放行 200) ==="
curl -sk -o /dev/null -w "HTTP %{http_code}\n" "$URL"

echo "=== 2. SQL注入 (应拦截 403) ==="
curl -sk -o /dev/null -w "HTTP %{http_code}\n" "${URL}?id=1+union+select+1"

echo "=== 3. 扫描器 UA (应拦截 403) ==="
curl -sk -o /dev/null -w "HTTP %{http_code}\n" -A "sqlmap/1.0" "$URL"

echo "=== 4. 路径遍历 (应拦截 403) ==="
curl -sk -o /dev/null -w "HTTP %{http_code}\n" "https://sub.wyfc.qzz.io/../etc/passwd"

echo "=== 5. XSS (应拦截 403) ==="
curl -sk -o /dev/null -w "HTTP %{http_code}\n" "${URL}?q=<script>alert(1)</script>"

echo "=== 6. POST 注入 (应拦截 403) ==="
curl -sk -o /dev/null -w "HTTP %{http_code}\n" -d "id=1 union select 1,2,3" "$URL"

echo "=== 7. Cookie 注入 (应拦截 403) ==="
curl -sk -o /dev/null -w "HTTP %{http_code}\n" -b "session=union select from" "$URL"

echo "=== 8. Referer 检测 (应拦截 403) ==="
curl -sk -o /dev/null -w "HTTP %{http_code}\n" -e "http://evil.pay.com/" "$URL"

echo "=== 9. 白名单 IP 8.8.8.8 (应放行 200) ==="
curl -sk -o /dev/null -w "HTTP %{http_code}\n" -H "X-Forwarded-For: 8.8.8.8" "${URL}?id=union+select"

echo ""
echo "=== WAF 日志 ==="
LOGFILE="/var/log/caddyguard/$(date +%Y-%m-%d)_waf.log"
if [ -f "$LOGFILE" ]; then
  echo "日志条数: $(wc -l < $LOGFILE)"
  cat "$LOGFILE" | python3 -c "
import sys, json
from collections import Counter
methods = Counter()
for line in sys.stdin:
    try:
        d = json.loads(line.strip())
        methods[d.get('attack_method','unknown')] += 1
    except: pass
for m, c in methods.most_common():
    print(f'  {m}: {c}次')
" 2>/dev/null
fi

kill $CADDY_PID 2>/dev/null
wait $CADDY_PID 2>/dev/null
