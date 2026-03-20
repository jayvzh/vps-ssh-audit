#!/bin/bash

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT="ssh_audit_report.txt"
TMP_ALL="all_logs.tmp"
TMP_RECENT="recent_logs.tmp"
TMP_PARSED="parsed.log"
TMP_STATS="stats.tmp"
IP_CACHE="ip_cache.txt"
UNIQUE_IPS="unique_ips.txt"

DEFAULT_LOG_DIR="/var/log"
DEFAULT_DAYS=7
DEFAULT_DO_GEO="Y"

LOG_DIR=""
DAYS=""
DO_GEO=""
REGION=""
USE_JOURNALCTL=false

show_help() {
    cat << EOF
SSH 登录审计脚本

用法: $(basename "$0") [选项]

选项:
    -y              使用默认值，跳过交互式输入
    -d <目录>       指定日志目录 (默认: /var/log)
    -n <天数>       指定审计天数 (默认: 7)
    -g <Y/n>        是否查询归属地 (默认: Y)
    -h              显示帮助信息

示例:
    $(basename "$0")              # 交互式运行
    $(basename "$0") -y           # 使用默认值运行
    $(basename "$0") -d /var/log -n 30 -g Y   # 指定参数运行
EOF
}

cleanup() {
    rm -f "$TMP_ALL" "$TMP_RECENT" "$TMP_PARSED" "$TMP_STATS" "$UNIQUE_IPS"
}

trap cleanup EXIT

detect_region() {
    echo "[*] 检测服务器所在地区..."
    local country
    country=$(curl -s --connect-timeout 5 "http://ip-api.com/json/?fields=countryCode" 2>/dev/null | grep -o '"countryCode":"[^"]*"' | cut -d'"' -f4)
    if [[ "$country" == "CN" ]]; then
        echo "china"
    else
        echo "international"
    fi
}

get_geo_international() {
    local ip="$1"
    local geo
    geo=$(curl -s --connect-timeout 5 "http://ip-api.com/json/$ip?fields=country,regionName,city" 2>/dev/null | \
        awk -F'"' '{print $4" "$8" "$12}')
    if [[ -z "$geo" || "$geo" == "  " ]]; then
        echo "未知"
    else
        echo "$geo"
    fi
}

get_geo_china() {
    local ip="$1"
    local geo
    geo=$(curl -s --connect-timeout 5 "http://whois.pconline.com.cn/ipJson.jsp?ip=$ip&json=true" 2>/dev/null | \
        grep -o '"pro":"[^"]*"\|"city":"[^"]*"' | tr '\n' ' ' | sed 's/"pro":"//g; s/"city":"//g; s/"//g' | awk '{print $1,$2}')
    if [[ -z "$geo" ]]; then
        geo=$(get_geo_international "$ip")
    fi
    echo "$geo"
}

get_geo() {
    local ip="$1"
    local geo
    geo=$(grep "^$ip " "$IP_CACHE" 2>/dev/null | cut -d' ' -f2-)
    
    if [[ -z "$geo" ]]; then
        if [[ "$REGION" == "china" ]]; then
            geo=$(get_geo_china "$ip")
        else
            geo=$(get_geo_international "$ip")
        fi
        echo "$ip $geo" >> "$IP_CACHE"
    fi
    
    echo "$geo"
}

detect_log_format() {
    local line="$1"
    if [[ "$line" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T ]]; then
        echo "iso8601"
    elif [[ "$line" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}\ [0-9]{2}: ]]; then
        echo "short-iso"
    else
        echo "syslog"
    fi
}

parse_syslog() {
    awk '/Accepted/ {
        ip=""
        method=""
        user=""
        for(i=1;i<=NF;i++){
            if($i=="for"){user=$(i+1)}
            if($i=="from"){ip=$(i+1)}
            if($i~"publickey|password|keyboard-interactive"){method=$i}
        }
        if(ip!="" && user!=""){
            print $1,$2,$3,"|",user,"|",ip,"|",method
        }
    }' "$1"
}

parse_iso8601() {
    awk '/Accepted/ {
        ip=""
        method=""
        user=""
        datetime=$1
        for(i=1;i<=NF;i++){
            if($i=="for"){user=$(i+1)}
            if($i=="from"){ip=$(i+1)}
            if($i~"publickey|password|keyboard-interactive"){method=$i}
        }
        if(ip!="" && user!=""){
            print datetime,"|",user,"|",ip,"|",method
        }
    }' "$1"
}

parse_short_iso() {
    awk '/Accepted/ {
        ip=""
        method=""
        user=""
        datetime=$1" "$2
        for(i=1;i<=NF;i++){
            if($i=="for"){user=$(i+1)}
            if($i=="from"){ip=$(i+1)}
            if($i~"publickey|password|keyboard-interactive"){method=$i}
        }
        if(ip!="" && user!=""){
            print datetime,"|",user,"|",ip,"|",method
        }
    }' "$1"
}

filter_recent_syslog() {
    local days="$1"
    local current_year
    current_year=$(date +%Y)
    
    awk -v days="$days" -v year="$current_year" '
    BEGIN {
        split("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec", months)
        for(i=1;i<=12;i++) month_num[months[i]]=i
    }
    {
        mon=$1
        day=$2
        time=$3
        if(mon in month_num) {
            log_date=sprintf("%04d-%02d-%02d", year, month_num[mon], day)
            print log_date,time,$4,$5,$6,$7,$8,$9,$10
        }
    }' "$TMP_PARSED" | awk -v days="$days" '
    BEGIN {
        now=systime()
        cutoff=now-(days*86400)
    }
    {
        log_ts=mktime(gensub(/-| |:/, " ", "g", $1" "$2))
        if(log_ts>=cutoff || log_ts==0) print
    }'
}

filter_recent_iso() {
    local days="$1"
    awk -v days="$days" '
    BEGIN {
        now=systime()
        cutoff=now-(days*86400)
    }
    {
        datetime=$1
        gsub(/T|Z/," ",datetime)
        gsub(/\+/," ",datetime)
        split(datetime,parts," ")
        dt=parts[1]" "parts[2]
        log_ts=mktime(gensub(/-| |:/, " ", "g", dt))
        if(log_ts>=cutoff || log_ts==0) print
    }' "$TMP_PARSED"
}

collect_logs() {
    local log_dir="$1"
    local found_logs=false
    
    > "$TMP_ALL"
    
    for pattern in "auth.log*" "secure*" "messages*"; do
        for file in "$log_dir"/$pattern; do
            if [[ -f "$file" ]]; then
                found_logs=true
                if [[ "$file" == *.gz ]]; then
                    zcat "$file" >> "$TMP_ALL" 2>/dev/null
                else
                    cat "$file" >> "$TMP_ALL" 2>/dev/null
                fi
            fi
        done
    done
    
    if [[ "$found_logs" == false ]]; then
        if command -v journalctl &>/dev/null; then
            echo "[*] 未找到日志文件，尝试使用 journalctl..."
            USE_JOURNALCTL=true
            journalctl -u sshd --no-pager 2>/dev/null >> "$TMP_ALL" || \
            journalctl -u ssh --no-pager 2>/dev/null >> "$TMP_ALL" || true
        fi
    fi
    
    if [[ ! -s "$TMP_ALL" ]]; then
        echo "[!] 错误: 未找到任何SSH日志"
        exit 1
    fi
}

interactive_input() {
    if [[ "$USE_DEFAULT" == true ]]; then
        LOG_DIR="${LOG_DIR:-$DEFAULT_LOG_DIR}"
        DAYS="${DAYS:-$DEFAULT_DAYS}"
        DO_GEO="${DO_GEO:-$DEFAULT_DO_GEO}"
        return
    fi
    
    read -p "请输入日志目录 [默认: $DEFAULT_LOG_DIR]: " input
    LOG_DIR="${input:-$DEFAULT_LOG_DIR}"
    
    read -p "请输入审计天数 [默认: $DEFAULT_DAYS]: " input
    DAYS="${input:-$DEFAULT_DAYS}"
    
    read -p "是否查询IP归属地? [Y/n]: " input
    DO_GEO="${input:-$DEFAULT_DO_GEO}"
}

main() {
    USE_DEFAULT=false
    
    while getopts "yd:n:g:h" opt; do
        case $opt in
            y) USE_DEFAULT=true ;;
            d) LOG_DIR="$OPTARG" ;;
            n) DAYS="$OPTARG" ;;
            g) DO_GEO="$OPTARG" ;;
            h) show_help; exit 0 ;;
            *) show_help; exit 1 ;;
        esac
    done
    
    interactive_input
    
    LOG_DIR="${LOG_DIR:-$DEFAULT_LOG_DIR}"
    DAYS="${DAYS:-$DEFAULT_DAYS}"
    DO_GEO="${DO_GEO:-$DEFAULT_DO_GEO}"
    DO_GEO=$(echo "$DO_GEO" | tr '[:lower:]' '[:upper:]')
    
    if [[ ! -d "$LOG_DIR" ]]; then
        echo "[!] 错误: 日志目录不存在: $LOG_DIR"
        exit 1
    fi
    
    echo "========================================"
    echo "SSH 登录审计工具"
    echo "========================================"
    echo "[*] 日志目录: $LOG_DIR"
    echo "[*] 审计天数: $DAYS"
    echo "[*] 查询归属地: $DO_GEO"
    echo ""
    
    if [[ "$DO_GEO" == "Y" ]]; then
        REGION=$(detect_region)
        if [[ "$REGION" == "china" ]]; then
            echo "[*] 检测到国内环境，使用国内API查询归属地"
        else
            echo "[*] 检测到国外环境，使用国际API查询归属地"
        fi
    fi
    
    echo "[*] 收集日志文件..."
    collect_logs "$LOG_DIR"
    
    echo "[*] 检测日志格式..."
    FIRST_LINE=$(head -1 "$TMP_ALL")
    LOG_FORMAT=$(detect_log_format "$FIRST_LINE")
    echo "[*] 检测到日志格式: $LOG_FORMAT"
    
    echo "[*] 解析SSH登录记录..."
    case "$LOG_FORMAT" in
        syslog) parse_syslog "$TMP_ALL" > "$TMP_PARSED" ;;
        iso8601) parse_iso8601 "$TMP_ALL" > "$TMP_PARSED" ;;
        short-iso) parse_short_iso "$TMP_ALL" > "$TMP_PARSED" ;;
    esac
    
    if [[ ! -s "$TMP_PARSED" ]]; then
        echo "[!] 未找到SSH成功登录记录"
        exit 0
    fi
    
    touch "$IP_CACHE"
    
    echo "[*] 生成审计报告..."
    
    echo "==== SSH 审计报告 ====" > "$OUTPUT"
    echo "生成时间: $(date '+%Y-%m-%d %H:%M:%S')" >> "$OUTPUT"
    echo "日志目录: $LOG_DIR" >> "$OUTPUT"
    echo "审计范围: 最近 $DAYS 天" >> "$OUTPUT"
    echo "" >> "$OUTPUT"
    
    echo "==== 本机信息 ====" >> "$OUTPUT"
    echo "Hostname: $(hostname)" >> "$OUTPUT"
    LOCAL_IP=$(curl -s --connect-timeout 5 ifconfig.me 2>/dev/null || echo "获取失败")
    echo "IP: $LOCAL_IP" >> "$OUTPUT"
    if [[ "$DO_GEO" == "Y" && "$LOCAL_IP" != "获取失败" ]]; then
        LOCAL_GEO=$(get_geo "$LOCAL_IP")
        echo "地区: $LOCAL_GEO" >> "$OUTPUT"
    fi
    echo "" >> "$OUTPUT"
    
    echo "[*] 筛选最近 $DAYS 天的记录..."
    case "$LOG_FORMAT" in
        syslog) filter_recent_syslog "$DAYS" > "$TMP_RECENT" ;;
        iso8601|short-iso) filter_recent_iso "$DAYS" > "$TMP_RECENT" ;;
    esac
    
    echo "==== 最近${DAYS}天登录明细 ====" >> "$OUTPUT"
    if [[ -s "$TMP_RECENT" ]]; then
        while IFS= read -r line; do
            ip=$(echo "$line" | awk -F'|' '{print $3}' | tr -d ' ')
            if [[ "$DO_GEO" == "Y" ]]; then
                geo=$(get_geo "$ip")
                echo "$line | $geo" >> "$OUTPUT"
            else
                echo "$line" >> "$OUTPUT"
            fi
        done < "$TMP_RECENT"
    else
        echo "无记录" >> "$OUTPUT"
    fi
    echo "" >> "$OUTPUT"
    
    echo "==== 历史IP统计（全量） ====" >> "$OUTPUT"
    
    awk -F'|' '
    {
        ip=$3
        gsub(/ /,"",ip)
        count[ip]++
        if (!first[ip]) first[ip]=$1
        last[ip]=$1
    }
    END {
        for (ip in count) {
            print ip,"| 次数:",count[ip],"| 首次:",first[ip],"| 最近:",last[ip]
        }
    }' "$TMP_PARSED" > "$TMP_STATS"
    
    while IFS= read -r line; do
        ip=$(echo "$line" | awk '{print $1}')
        if [[ "$DO_GEO" == "Y" ]]; then
            geo=$(get_geo "$ip")
            echo "$line | $geo" >> "$OUTPUT"
        else
            echo "$line" >> "$OUTPUT"
        fi
    done < "$TMP_STATS"
    echo "" >> "$OUTPUT"
    
    echo "==== 风险提示 ====" >> "$OUTPUT"
    RISK_COUNT=0
    while IFS= read -r line; do
        if [[ "$line" =~ \|[\ ]*root[\ ]*\| ]]; then
            echo "[!] 发现 root 用户登录: $line" >> "$OUTPUT"
            ((RISK_COUNT++))
        fi
    done < "$TMP_PARSED"
    
    if [[ $RISK_COUNT -eq 0 ]]; then
        echo "未发现 root 用户登录" >> "$OUTPUT"
    else
        echo "" >> "$OUTPUT"
        echo "共发现 $RISK_COUNT 次 root 用户登录，请关注安全风险！" >> "$OUTPUT"
    fi
    echo "" >> "$OUTPUT"
    
    LOGIN_COUNT=$(wc -l < "$TMP_PARSED")
    UNIQUE_IP_COUNT=$(cut -d'|' -f3 "$TMP_PARSED" | tr -d ' ' | sort -u | wc -l)
    
    echo "==== 统计摘要 ====" >> "$OUTPUT"
    echo "总登录次数: $LOGIN_COUNT" >> "$OUTPUT"
    echo "唯一IP数量: $UNIQUE_IP_COUNT" >> "$OUTPUT"
    echo "root登录次数: $RISK_COUNT" >> "$OUTPUT"
    
    echo ""
    echo "========================================"
    echo "[✓] 报告生成完成: $OUTPUT"
    echo "========================================"
}

main "$@"
