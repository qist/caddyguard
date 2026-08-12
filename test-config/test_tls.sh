#!/bin/bash
# sub.wyfc.qzz.io TLS + WAF + 子域名配置测试
mkdir -p /var/log/caddyguard

# 清理旧日志
rm -f /var/log/caddyguard/*_waf.log

# 启动后端 8081
python3 -c "
from http.server import HTTPServer, BaseHTTPRequestHandler
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        self.wfile.write(b'Backend 8081 OK')
    def do_POST(self):
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        self.wfile.write(b'Backend 8081 POST OK')
    def log_message(self, *a): pass
HTTPServer(('127.0.0.1', 8081), H).serve_forever()
" &
B1=$!

# 启动后端 8080
python3 -c "
from http.server import HTTPServer, BaseHTTPRequestHandler
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        self.wfile.write(b'Backend 8080 OK')
    def do_POST(self):
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        self.wfile.write(b'Backend 8080 POST OK')
    def log_message(self, *a): pass
HTTPServer(('127.0.0.1', 8080), H).serve_forever()
" &
B2=$!

sleep 1

# 启动 caddy
/opt/caddy-binaries/caddy run --config /opt/caddyguard/test-config/Caddyfile --adapter caddyfile 2>/dev/null &
CADDY_PID=$!
sleep 3

DOMAIN="sub.wyfc.qzz.io"

echo "========================================="
echo "HTTPS $DOMAIN:8443 测试"
echo "(domain.json: post_enable=off, cc_rate=500)"
echo "========================================="

echo ""
echo "--- 1. 正常 GET (应放行 200) ---"
curl -sk -o /dev/null -w "HTTP %{http_code}\n" --resolve $DOMAIN:8443:127.0.0.1 https://$DOMAIN:8443/

echo "--- 2. SQL注入 GET (应拦截 403) ---"
curl -sk -o /dev/null -w "HTTP %{http_code}\n" --resolve $DOMAIN:8443:127.0.0.1 "https://$DOMAIN:8443/?id=1+union+select+1"

echo "--- 3. 路径遍历 (应拦截 403) ---"
curl -sk -o /dev/null -w "HTTP %{http_code}\n" --resolve $DOMAIN:8443:127.0.0.1 "https://$DOMAIN:8443/../etc/passwd"

echo "--- 4. 扫描器 UA (应拦截 403) ---"
curl -sk -o /dev/null -w "HTTP %{http_code}\n" --resolve $DOMAIN:8443:127.0.0.1 -A "sqlmap/1.0" https://$DOMAIN:8443/

echo "--- 5. XSS (应拦截 403) ---"
curl -sk -o /dev/null -w "HTTP %{http_code}\n" --resolve $DOMAIN:8443:127.0.0.1 "https://$DOMAIN:8443/?q=<script>alert(1)</script>"

echo "--- 6. Cookie 注入 (应拦截 403) ---"
curl -sk -o /dev/null -w "HTTP %{http_code}\n" --resolve $DOMAIN:8443:127.0.0.1 -b "session=union select from" https://$DOMAIN:8443/

echo "--- 7. Referer 检测 (应拦截 403) ---"
curl -sk -o /dev/null -w "HTTP %{http_code}\n" --resolve $DOMAIN:8443:127.0.0.1 -e "http://evil.pay.com/" https://$DOMAIN:8443/

echo ""
echo "========================================="
echo "POST 注入测试 (domain.json: post_enable=off)"
echo "========================================="
echo "--- 8. POST 注入 (应放行 200, 因 post_enable=off) ---"
curl -sk -o /dev/null -w "HTTP %{http_code}\n" --resolve $DOMAIN:8443:127.0.0.1 -d "id=1 union select 1,2,3" https://$DOMAIN:8443/

echo ""
echo "========================================="
echo "白名单测试"
echo "========================================="
echo "--- 9. 白名单 IP 8.8.8.8 + SQL注入 (应放行 200) ---"
curl -sk -o /dev/null -w "HTTP %{http_code}\n" --resolve $DOMAIN:8443:127.0.0.1 -H "X-Forwarded-For: 8.8.8.8" "https://$DOMAIN:8443/?id=union+select"

echo "--- 10. 白名单 URL /123/ (应放行, 后端404) ---"
curl -sk -o /dev/null -w "HTTP %{http_code}\n" --resolve $DOMAIN:8443:127.0.0.1 "https://$DOMAIN:8443/123/"

echo ""
echo "========================================="
echo "HTTP :80 测试"
echo "========================================="
echo "--- 11. 正常请求 (应放行 200) ---"
curl -s -o /dev/null -w "HTTP %{http_code}\n" http://localhost:80/

echo "--- 12. SQL注入 (应拦截 403) ---"
curl -s -o /dev/null -w "HTTP %{http_code}\n" "http://localhost:80/?id=1+union+select+1"

echo ""
echo "========================================="
echo "WAF 日志检查"
echo "========================================="
LOGFILE="/var/log/caddyguard/$(date +%Y-%m-%d)_waf.log"
if [ -f "$LOGFILE" ]; then
  echo "日志条数: $(wc -l < $LOGFILE)"
  echo "--- 按攻击类型统计 ---"
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
  echo "--- 最后3条日志 ---"
  tail -3 "$LOGFILE" | python3 -c "
import sys, json
for line in sys.stdin:
    try:
        d = json.loads(line.strip())
        print(f\"  [{d['attack_method']}] {d['client_ip']} {d['req_url']} -> {d['rule_tag'][:50]}\")
    except: pass
" 2>/dev/null
else
  echo "未找到日志文件"
fi

# 清理
kill $CADDY_PID $B1 $B2 2>/dev/null
wait $CADDY_PID $B1 $B2 2>/dev/null
