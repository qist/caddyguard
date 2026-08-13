#!/bin/bash
pkill caddy 2>/dev/null
sleep 1
nohup /opt/caddyguard/caddy run --config /opt/caddyguard/test-config/Caddyfile.backend --adapter caddyfile > /tmp/cb.log 2>&1 &
sleep 1
nohup /opt/caddyguard/caddy run --config /opt/caddyguard/test-config/Caddyfile.A --adapter caddyfile > /tmp/cw.log 2>&1 &
sleep 2
WAFPID=$(pgrep -f Caddyfile.A | head -1)
echo "WAFPID=$WAFPID"
pidstat -u -r -h -p $WAFPID 1 15 > /tmp/pidstat_A_final.txt 2>/dev/null &
PIDSTAT_PID=$!
sleep 2
ab -n 50000 -c 200 -H "User-Agent: Mozilla/5.0" http://127.0.0.1:8888/ > /tmp/ab_A_final.txt 2>&1
sleep 2
kill $PIDSTAT_PID 2>/dev/null
wait $PIDSTAT_PID 2>/dev/null
echo "=== pidstat raw ==="
cat /tmp/pidstat_A_final.txt
echo "=== analysis ==="
awk 'NR>3 && $9 ~ /^[0-9]/ {cpu+=$9; n++; if($14>rss) rss=$14} END{if(n>0) printf "CPU=%.0f%% RSS=%dKB\n", cpu/n, rss; else print "no data"}' /tmp/pidstat_A_final.txt
echo "=== ab result ==="
grep "Requests per second" /tmp/ab_A_final.txt
grep " 99%" /tmp/ab_A_final.txt
