#!/bin/bash
# CaddyGuard 11/06 同步功能回归测试（nginxguard 9/17→11/06）
# 覆盖三项新功能: ①fileext 大小写不敏感 ②domain.json 逗号分隔多域名 key ③同步的新规则
# 在 180 本地执行（也可 CADDY=... 指定测试二进制）
#
# 用例来源（本地单测对齐）: TestFileUploadCaseInsensitive / TestDomainMultiKeyExpansion

CADDY="${CADDY:-/opt/caddyguard/caddy}"
CONF_DIR="/opt/caddyguard/test-config"
RULE_DIR="/opt/caddyguard/rule-config"
STAGE_DIR="/tmp/rules-sync"          # scp 上传的同步后规则文件
TARGET="http://127.0.0.1:8888"
HOSTBASE="https://gameapi.qkagame.com"  # --resolve 用, 不在 domain.json 覆盖列表中
PASS=0
FAIL=0
ERRORS=""

# 备份原始配置, 退出时恢复
BAK=/tmp/sync1106_bak
mkdir -p $BAK/domains_www
for f in config.json domain.json fileext.rule url.rule args.rule useragent.rule header.rule whiteip.rule post.rule; do
    [ -f $RULE_DIR/$f ] && cp -f $RULE_DIR/$f $BAK/$f
done
[ -f $RULE_DIR/domains/www.example.com/whiteip.rule ] && cp -f $RULE_DIR/domains/www.example.com/whiteip.rule $BAK/domains_www/whiteip.rule
restore_cfg() {
    for f in config.json domain.json fileext.rule url.rule args.rule useragent.rule header.rule whiteip.rule post.rule; do
        [ -f $BAK/$f ] && cp -f $BAK/$f $RULE_DIR/$f
    done
    [ -f $BAK/domains_www/whiteip.rule ] && cp -f $BAK/domains_www/whiteip.rule $RULE_DIR/domains/www.example.com/whiteip.rule
}
trap restore_cfg EXIT

# 写 config.json（CC 关闭以隔离检测项）
set_config() {
    cat > $RULE_DIR/config.json << EOF
{"waf_enable":"on","trust_proxy_headers":"on","log_dir":"/tmp","white_url_check":"on","white_ip_check":"on","white_ua_check":"on","black_ip_check":"on","url_check":"on","url_args_check":"on","user_agent_check":"on","header_check":"on","cookie_check":"on","cc_check":"off","cc_mode":"ip","cc_rate":"10/60","cc_block_ttl":0,"post_check":"on","referer_check":"off","file_upload_check":"on","waf_output":"html"}
EOF
}

# 安装同步后的规则文件
install_staged_rules() {
    for f in args.rule header.rule post.rule url.rule useragent.rule whiteip.rule domain.json; do
        [ -f $STAGE_DIR/$f ] && cp -f $STAGE_DIR/$f $RULE_DIR/$f
    done
    [ -f $STAGE_DIR/domwww_whiteip.rule ] && cp -f $STAGE_DIR/domwww_whiteip.rule $RULE_DIR/domains/www.example.com/whiteip.rule
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

# 重启 WAF caddy: 清空内存状态 + 加载最新配置/规则
restart_waf() {
    kill_waf
    nohup $CADDY run --config $CONF_DIR/Caddyfile.WAF --adapter caddyguardfile > /tmp/caddy_waf.log 2>&1 &
    for i in $(seq 1 10); do
        code=$(curl -s -m 2 -o /dev/null -w "%{http_code}" -H "User-Agent: Mozilla/5.0" "$TARGET/" 2>/dev/null)
        [ "$code" != "000" ] && break
        sleep 1
    done
    n=$(pgrep -fc "run --config $CONF_DIR/Caddyfile.WAF")
    if [ "$n" != "1" ]; then
        echo "FATAL: 期望 1 个 WAF 进程, 实际 $n 个"
        exit 1
    fi
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
expect() { if [ "$3" = "$2" ]; then ok "$1" "$3"; else bad "$1" "$3" "$2"; fi }
expect_not() { if [ "$3" != "$2" ]; then ok "$1" "$3"; else bad "$1" "$3" "非$2"; fi }

# GET 请求（WAF caddy 仅监听 :8888 HTTP, 用 --resolve 指定域名映射）
hget() { # $1=host $2=path [额外 curl 参数...]
    local h="$1" p="$2"; shift 2
    curl -s -m 5 --globoff --resolve "$h:8888:127.0.0.1" -o /dev/null -w "%{http_code}" "$@" "http://$h:8888$p"
}
# multipart 上传
hupload() { # $1=host $2=保存到磁盘的文件 $3=上传时的 filename
    curl -s -m 5 --resolve "$1:8888:127.0.0.1" -o /dev/null -w "%{http_code}" \
        -X POST -F "file=@$2;filename=$3" "http://$1:8888/upload"
}

echo "========================================"
echo "  CaddyGuard 11/06 同步功能回归测试"
echo "  二进制: $CADDY"
echo "  $(date '+%Y-%m-%d %H:%M:%S')"
echo "========================================"

# 启动
kill $(pgrep -x caddy) 2>/dev/null || true
kill $(pgrep -f "run --config $CONF_DIR/Caddyfile.WAF") 2>/dev/null || true
kill $(pgrep -f "run --config $CONF_DIR/Caddyfile.backend") 2>/dev/null || true
sleep 1
start_backend

set_config
install_staged_rules
# Stage A 用确定性 fileext.rule（正则 \.php$ + 纯字符串 backdoor）
printf '\\.php$\nbackdoor\n' > $RULE_DIR/fileext.rule
# 清空 domain.json（避免 180 现有域名配置干扰）
printf '{"_comment":"test-placeholder"}\n' > $RULE_DIR/domain.json
restart_waf

code=$(hget gameapi.qkagame.com / -H "User-Agent: Mozilla/5.0")
if [ "$code" != "200" ]; then
    echo "FATAL: Caddy failed to start, HTTP $code"
    tail -20 /tmp/caddy_waf.log
    exit 1
fi
echo "Caddy started OK (HTTP 200)"

# 上传测试文件
printf 'MZ' > /tmp/up_test.bin

# ============================================================
# A. fileext 大小写不敏感（今日修复: .PHP/.Php 大写变体不可绕过）
# ============================================================
echo ""
echo "--- A. fileext 大小写不敏感 ---"
code=$(hupload gameapi.qkagame.com /tmp/up_test.bin shell.PHP)
expect "A1: shell.PHP 大写扩展名被拦截(修复前可绕过)" 403 "$code"
code=$(hupload gameapi.qkagame.com /tmp/up_test.bin evil.Backdoor)
expect "A2: evil.Backdoor 纯字符串规则大小写混合命中" 403 "$code"
code=$(hupload gameapi.qkagame.com /tmp/up_test.bin shell.php)
expect "A3: shell.php 小写正常拦截" 403 "$code"
code=$(hupload gameapi.qkagame.com /tmp/up_test.bin report.pdf)
expect_not "A4: report.pdf 正常文件放行" 403 "$code"

# ============================================================
# B. domain.json 逗号分隔多域名 key 展开（今日新功能）
#    攻击载荷: X-Original-URL 绕过头, header.rule 拦截 → 403
#    header_check=off 的域名 → 200
# ============================================================
echo "--- B1. 逗号 key 展开共享配置 ---"
printf '{"h1.sync.test, h2.sync.test": {"header_check": "off"}}\n' > $RULE_DIR/domain.json
restart_waf
code=$(hget h1.sync.test / -H "User-Agent: Mozilla/5.0" -H "X-Original-URL: /admin")
expect "B1a: h1.sync.test 展开条目 header_check=off" 200 "$code"
code=$(hget h2.sync.test / -H "User-Agent: Mozilla/5.0" -H "X-Original-URL: /admin")
expect "B1b: h2.sync.test 展开条目共享同一配置" 200 "$code"
code=$(hget h4.sync.test / -H "User-Agent: Mozilla/5.0" -H "X-Original-URL: /admin")
expect "B1c: h4.sync.test 未配置域名正常检测" 403 "$code"

echo "--- B2. 显式单域名 key 优先 ---"
printf '{"h1.sync.test, h2.sync.test": {"header_check": "off"}, "h1.sync.test": {"header_check": "on"}}\n' > $RULE_DIR/domain.json
restart_waf
code=$(hget h1.sync.test / -H "User-Agent: Mozilla/5.0" -H "X-Original-URL: /admin")
expect "B2a: h1.sync.test 显式 key 覆盖展开(on)" 403 "$code"
code=$(hget h2.sync.test / -H "User-Agent: Mozilla/5.0" -H "X-Original-URL: /admin")
expect "B2b: h2.sync.test 仍走展开配置(off)" 200 "$code"

echo "--- B3. 子域名 trim + 转小写 ---"
printf '{" H5.SYNC.TESt , h6.sync.test ": {"header_check": "off"}}\n' > $RULE_DIR/domain.json
restart_waf
code=$(hget h5.sync.test / -H "User-Agent: Mozilla/5.0" -H "X-Original-URL: /admin")
expect "B3a: H5.SYNC.TESt trim+小写后匹配 h5.sync.test" 200 "$code"
code=$(hget h6.sync.test / -H "User-Agent: Mozilla/5.0" -H "X-Original-URL: /admin")
expect "B3b: h6.sync.test 前导空格 trim 后匹配" 200 "$code"

# ============================================================
# C. 同步的新规则抽查（恢复原始 domain.json）
# ============================================================
echo "--- C. 同步规则抽查 ---"
if [ -f $BAK/domain.json ]; then cp -f $BAK/domain.json $RULE_DIR/domain.json; else printf '{"_comment":"test-placeholder"}\n' > $RULE_DIR/domain.json; fi
if [ -f $BAK/fileext.rule ]; then cp -f $BAK/fileext.rule $RULE_DIR/fileext.rule; fi
restart_waf
code=$(hget gameapi.qkagame.com /jenkins/script -H "User-Agent: Mozilla/5.0")
expect "C1: url.rule 新增 /jenkins/ 拦截" 403 "$code"
code=$(hget gameapi.qkagame.com '/?s=/index/%5Cthink%5Capp%5Cinvokefunction&func=call_user_func_array' -H "User-Agent: Mozilla/5.0" --globoff)
expect "C2: ThinkPHP invokefunction RCE 拦截" 403 "$code"
code=$(hget gameapi.qkagame.com / -A "l9scan/2.0.1")
expect "C3: useragent.rule 新增 l9scan 拦截" 403 "$code"
code=$(hget gameapi.qkagame.com /wp-json/wp/v2/users -H "User-Agent: Mozilla/5.0")
expect "C4: url.rule 新增 /wp-json 拦截" 403 "$code"
code=$(hget gameapi.qkagame.com / -H "User-Agent: Mozilla/5.0")
expect_not "C5: 正常请求放行" 403 "$code"

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
echo "配置与规则已恢复, caddy 已停止"
echo "Done!"
