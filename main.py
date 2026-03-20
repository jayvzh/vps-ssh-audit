import os
import re
import gzip
import json
import time
import sys
import ipaddress
import requests
from datetime import datetime, timedelta
from collections import defaultdict

# ===== 配置 =====
IP_CACHE_FILE = "ip_cache.json"
MAX_RETRIES = 3
RETRY_DELAY = 1.0
REQUEST_TIMEOUT = 5


def get_app_dir():
    """获取应用程序所在目录（兼容PyInstaller打包）"""
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))

# ===== IP 辅助函数 =====

def is_private_ip(ip):
    """判断是否为内网 IP"""
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
    except ValueError:
        return False

def get_ip_segment(ip):
    """获取 IP 段标识（IPv4 取前3段，IPv6 取前64位）"""
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.version == 4:
            parts = str(ip_obj).split('.')
            return '.'.join(parts[:3]) + '.0/24'
        else:
            return str(ipaddress.ip_network(f"{ip_obj}/64", strict=False))
    except ValueError:
        return ip

def get_representative_ips(unique_ips):
    """从 IP 列表中获取代表性 IP（每段一个，排除内网）"""
    segment_map = {}
    private_ips = []
    
    for ip in unique_ips:
        if is_private_ip(ip):
            private_ips.append(ip)
            continue
        
        segment = get_ip_segment(ip)
        if segment not in segment_map:
            segment_map[segment] = ip
    
    return list(segment_map.values()), private_ips

# ===== 工具函数 =====

def load_cache():
    if os.path.exists(IP_CACHE_FILE):
        try:
            with open(IP_CACHE_FILE, "r", encoding="utf-8") as f:
                cache = json.load(f)
            
            migrated_cache = {}
            for key, value in cache.items():
                if '/' in key:
                    migrated_cache[key] = value
                else:
                    try:
                        ipaddress.ip_address(key)
                        segment = get_ip_segment(key)
                        if segment not in migrated_cache:
                            migrated_cache[segment] = value
                    except ValueError:
                        migrated_cache[key] = value
            
            return migrated_cache
        except (json.JSONDecodeError, IOError) as e:
            print(f"警告: 缓存文件读取失败，将使用空缓存 ({e})")
            return {}
    return {}

def save_cache(cache):
    try:
        with open(IP_CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(cache, f, indent=2, ensure_ascii=False)
    except IOError as e:
        print(f"警告: 缓存文件保存失败 ({e})")

def get_ip_geo(ip, cache, enable_query=True):
    segment = get_ip_segment(ip)
    
    if segment in cache:
        return cache[segment]

    if not enable_query:
        result = {"country": "", "region": "", "city": "", "org": "", "status": "disabled"}
        cache[segment] = result
        return result

    url = f"https://ipinfo.io/{ip}/json"
    last_error = None

    for attempt in range(MAX_RETRIES):
        try:
            res = requests.get(url, timeout=REQUEST_TIMEOUT)

            if res.status_code == 429:
                last_error = "RateLimited"
                if attempt < MAX_RETRIES - 1:
                    wait_time = RETRY_DELAY * (attempt + 1) * 2
                    print(f"  IP {ip}: API 限制，等待 {wait_time}秒后重试...")
                    time.sleep(wait_time)
                continue

            if res.status_code != 200:
                last_error = f"HTTP_{res.status_code}"
                if attempt < MAX_RETRIES - 1:
                    time.sleep(RETRY_DELAY)
                continue

            data = res.json()

            if "bogon" in data and data["bogon"]:
                result = {"country": "", "region": "", "city": "", "org": "", "status": "bogon"}
                cache[segment] = result
                return result

            result = {
                "country": data.get("country", ""),
                "region": data.get("region", ""),
                "city": data.get("city", ""),
                "org": data.get("org", ""),
                "status": "success"
            }
            cache[segment] = result
            return result

        except requests.exceptions.Timeout:
            last_error = "Timeout"
            if attempt < MAX_RETRIES - 1:
                print(f"  IP {ip}: 请求超时，重试 {attempt + 2}/{MAX_RETRIES}...")
                time.sleep(RETRY_DELAY)

        except requests.exceptions.ConnectionError:
            last_error = "ConnectionError"
            if attempt < MAX_RETRIES - 1:
                print(f"  IP {ip}: 连接错误，重试 {attempt + 2}/{MAX_RETRIES}...")
                time.sleep(RETRY_DELAY)

        except requests.exceptions.RequestException as e:
            last_error = f"RequestError: {type(e).__name__}"
            if attempt < MAX_RETRIES - 1:
                time.sleep(RETRY_DELAY)

        except json.JSONDecodeError:
            last_error = "InvalidJSON"
            if attempt < MAX_RETRIES - 1:
                time.sleep(RETRY_DELAY)

    result = {"country": "", "region": "", "city": "", "org": "", "status": last_error or "QueryFailed"}
    cache[segment] = result
    return result

def format_geo_info(geo_data):
    if isinstance(geo_data, str):
        return geo_data
    if not isinstance(geo_data, dict):
        return "Unknown"

    status = geo_data.get("status", "unknown")
    if status == "private":
        return "内网地址"
    if status == "disabled":
        return "查询已禁用"
    if status == "bogon":
        return "保留IP"
    if status == "RateLimited":
        return "API限制"
    if status == "Timeout":
        return "请求超时"
    if status == "ConnectionError":
        return "连接错误"
    if status not in ("success", ""):
        return f"查询失败({status})"

    parts = []
    for key in ["country", "region", "city", "org"]:
        val = geo_data.get(key, "")
        if val:
            parts.append(val)

    return " ".join(parts) if parts else "Unknown"

def open_log(file_path):
    if file_path.endswith(".gz"):
        return gzip.open(file_path, "rt", errors="ignore")
    else:
        return open(file_path, "r", errors="ignore")

def infer_year(month_str):
    current_year = datetime.now().year
    current_month = datetime.now().month

    month_map = {
        'Jan': 1, 'Feb': 2, 'Mar': 3, 'Apr': 4,
        'May': 5, 'Jun': 6, 'Jul': 7, 'Aug': 8,
        'Sep': 9, 'Oct': 10, 'Nov': 11, 'Dec': 12
    }

    log_month = month_map.get(month_str)
    if log_month is None:
        return current_year

    if log_month > current_month:
        return current_year - 1
    return current_year

def parse_line(line):
    if not line or not line.strip():
        return None

    if "Accepted" not in line:
        return None

    iso_pattern = re.compile(
        r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?[+-]\d{2}:?\d{2})\s+'  # ISO 8601 / journalctl short-iso
        r'(\S+)\s+'                                                               # 主机名
        r'sshd\[(\d+)\]:\s+'                                                      # sshd[进程ID]
        r'Accepted\s+(\S+)\s+'                                                    # 认证方法
        r'for\s+(\S+)\s+'                                                         # 用户名
        r'from\s+(\S+)\s+'                                                        # IP地址
        r'port\s+(\d+)',                                                          # 端口号
        re.IGNORECASE
    )

    match = iso_pattern.match(line.strip())
    if match:
        timestamp_str, hostname, pid, method, user, ip, port = match.groups()
        try:
            if '+' in timestamp_str:
                parts = timestamp_str.rsplit('+', 1)
                if len(parts[1]) == 4 and ':' not in parts[1]:
                    timestamp_str = f"{parts[0]}+{parts[1][:2]}:{parts[1][2:]}"
            elif '-' in timestamp_str[10:]:
                parts = timestamp_str.rsplit('-', 1)
                if len(parts[1]) == 4 and ':' not in parts[1]:
                    timestamp_str = f"{parts[0]}-{parts[1][:2]}:{parts[1][2:]}"
            dt = datetime.fromisoformat(timestamp_str)
            dt = dt.replace(tzinfo=None)
        except ValueError:
            return None
        date_str = dt.strftime("%b %d %H:%M:%S")
        return {
            "date": date_str,
            "user": user,
            "ip": ip,
            "method": method,
            "port": port,
            "hostname": hostname,
            "pid": pid,
            "dt": dt,
            "raw_line": line.strip()
        }

    log_pattern = re.compile(
        r'^(\w{3})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\s+'  # 月份 日期 时间
        r'(\S+)\s+'                                        # 主机名
        r'sshd\[(\d+)\]:\s+'                               # sshd[进程ID]
        r'Accepted\s+(\S+)\s+'                             # 认证方法
        r'for\s+(\S+)\s+'                                  # 用户名
        r'from\s+(\S+)\s+'                                 # IP地址
        r'port\s+(\d+)',                                   # 端口号
        re.IGNORECASE
    )

    match = log_pattern.match(line.strip())
    if not match:
        simple_pattern = re.compile(
            r'^(\w{3})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\s+'
            r'.*?Accepted\s+(\S+)\s+'
            r'for\s+(\S+)\s+'
            r'from\s+(\S+)',
            re.IGNORECASE
        )
        match = simple_pattern.match(line.strip())
        if not match:
            return None

        month, day, time_str, method, user, ip = match.groups()
        hostname = None
        pid = None
        port = None
    else:
        month, day, time_str, hostname, pid, method, user, ip, port = match.groups()

    try:
        year = infer_year(month)
        dt_str = f"{month} {day} {time_str}"
        dt = datetime.strptime(dt_str, "%b %d %H:%M:%S")
        dt = dt.replace(year=year)
    except ValueError:
        return None

    if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip) and not re.match(r'^[0-9a-fA-F:]+$', ip):
        return None

    return {
        "date": f"{month} {day} {time_str}",
        "user": user,
        "ip": ip,
        "method": method,
        "port": port,
        "hostname": hostname,
        "pid": pid,
        "dt": dt,
        "raw_line": line.strip()
    }

# ===== 风险检测 =====

RISK_LEVELS = {
    "HIGH": "高危",
    "MEDIUM": "中危",
    "LOW": "低危"
}

RISK_TYPES = {
    "ROOT_LOGIN_PUBLICKEY": "Root登录(公钥)",
    "ROOT_LOGIN_PASSWORD": "Root登录(密码)",
    "PASSWORD_AUTH": "密码认证登录",
    "HIGH_FREQUENCY_EXTERNAL": "高频外网IP",
    "HIGH_FREQUENCY_INTERNAL": "高频内网IP"
}

def is_reserved_ip(ip):
    """判断是否为保留IP（包括内网、回环、链路本地等）"""
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_reserved
    except ValueError:
        return False

def detect_risks(recent_logs, stats, threshold=10):
    risks = []
    
    root_login_ips = {}
    password_auth_ips = {}
    
    for r in recent_logs:
        if r["user"] == "root":
            ip = r["ip"]
            if ip not in root_login_ips:
                root_login_ips[ip] = {"count": 0, "methods": set(), "first_date": r["date"], "last_date": r["date"]}
            root_login_ips[ip]["count"] += 1
            root_login_ips[ip]["methods"].add(r["method"])
            root_login_ips[ip]["last_date"] = r["date"]

        if r["method"] == "password":
            ip = r["ip"]
            user = r["user"]
            if ip not in password_auth_ips:
                password_auth_ips[ip] = {"count": 0, "users": set(), "first_date": r["date"], "last_date": r["date"]}
            password_auth_ips[ip]["count"] += 1
            password_auth_ips[ip]["users"].add(user)
            password_auth_ips[ip]["last_date"] = r["date"]

    for ip, data in root_login_ips.items():
        is_private = is_reserved_ip(ip)
        methods = data["methods"]
        has_password = "password" in methods
        has_publickey = "publickey" in methods
        
        if is_private:
            if has_password:
                risks.append({
                    "level": "LOW",
                    "type": "ROOT_LOGIN_PASSWORD",
                    "ip": ip,
                    "count": data["count"],
                    "methods": list(methods),
                    "description": f"内网Root登录(密码认证)，IP: {ip}, 累计{data['count']}次"
                })
        else:
            if has_password:
                risks.append({
                    "level": "HIGH",
                    "type": "ROOT_LOGIN_PASSWORD",
                    "ip": ip,
                    "count": data["count"],
                    "methods": list(methods),
                    "description": f"外网Root登录(密码认证)，IP: {ip}, 累计{data['count']}次"
                })
            elif has_publickey:
                risks.append({
                    "level": "MEDIUM",
                    "type": "ROOT_LOGIN_PUBLICKEY",
                    "ip": ip,
                    "count": data["count"],
                    "methods": list(methods),
                    "description": f"外网Root登录(公钥认证)，IP: {ip}, 累计{data['count']}次"
                })

    for ip, data in password_auth_ips.items():
        is_private = is_reserved_ip(ip)
        users = data["users"]
        is_root = "root" in users
        
        if is_private:
            if not is_root:
                risks.append({
                    "level": "LOW",
                    "type": "PASSWORD_AUTH",
                    "ip": ip,
                    "count": data["count"],
                    "users": list(users),
                    "description": f"内网密码认证登录，IP: {ip}, 用户: {', '.join(users)}, 累计{data['count']}次"
                })
        else:
            if not is_root:
                risks.append({
                    "level": "MEDIUM",
                    "type": "PASSWORD_AUTH",
                    "ip": ip,
                    "count": data["count"],
                    "users": list(users),
                    "description": f"外网密码认证登录，IP: {ip}, 用户: {', '.join(users)}, 累计{data['count']}次"
                })

    for ip, s in stats.items():
        if s["count"] > threshold:
            is_private = is_reserved_ip(ip)
            
            if is_private:
                pass
            else:
                risks.append({
                    "level": "MEDIUM",
                    "type": "HIGH_FREQUENCY_EXTERNAL",
                    "ip": ip,
                    "count": s["count"],
                    "description": f"高频外网IP登录，IP: {ip}, 累计{s['count']}次 (阈值: {threshold})"
                })

    level_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    risks.sort(key=lambda x: (level_order.get(x["level"], 99), -(x.get("count") or 0)))

    return risks

# ===== HTML 报告生成 =====

def generate_html_report(recent_logs, stats, risks, cache, days, threshold, total_files, parsed_lines, total_ips, total_representative, total_private, output_path=None):
    html_content = f'''<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SSH 审计报告</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
            color: #333;
        }}
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            background: #fff;
            border-radius: 16px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }}
        .header {{
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            color: #fff;
            padding: 40px;
            text-align: center;
        }}
        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }}
        .header .subtitle {{
            font-size: 1.1em;
            opacity: 0.9;
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            padding: 30px;
            background: #f8f9fa;
        }}
        .stat-card {{
            background: #fff;
            padding: 25px;
            border-radius: 12px;
            text-align: center;
            box-shadow: 0 4px 15px rgba(0,0,0,0.1);
            transition: transform 0.3s ease;
        }}
        .stat-card:hover {{
            transform: translateY(-5px);
        }}
        .stat-card .number {{
            font-size: 2.5em;
            font-weight: bold;
            color: #667eea;
        }}
        .stat-card .label {{
            font-size: 0.9em;
            color: #666;
            margin-top: 5px;
        }}
        .section {{
            padding: 30px;
            border-bottom: 1px solid #eee;
        }}
        .section:last-child {{
            border-bottom: none;
        }}
        .section-title {{
            font-size: 1.5em;
            color: #1a1a2e;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 3px solid #667eea;
            display: inline-block;
        }}
        .table-container {{
            overflow-x: auto;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 0.9em;
        }}
        th {{
            background: #1a1a2e;
            color: #fff;
            padding: 15px 12px;
            text-align: left;
            font-weight: 600;
            white-space: nowrap;
        }}
        td {{
            padding: 12px;
            border-bottom: 1px solid #eee;
        }}
        tr:nth-child(even) {{
            background: #f8f9fa;
        }}
        tr:hover {{
            background: #e9ecef;
        }}
        .risk-section {{
            padding: 30px;
        }}
        .risk-summary {{
            display: flex;
            gap: 20px;
            margin-bottom: 25px;
            flex-wrap: wrap;
        }}
        .risk-badge {{
            padding: 15px 30px;
            border-radius: 8px;
            font-weight: bold;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        .risk-high {{
            background: linear-gradient(135deg, #ff416c, #ff4b2b);
            color: #fff;
        }}
        .risk-medium {{
            background: linear-gradient(135deg, #f7971e, #ffd200);
            color: #fff;
        }}
        .risk-low {{
            background: linear-gradient(135deg, #56ab2f, #a8e063);
            color: #fff;
        }}
        .risk-item {{
            padding: 15px 20px;
            margin-bottom: 10px;
            border-radius: 8px;
            border-left: 4px solid;
            background: #fff;
            box-shadow: 0 2px 8px rgba(0,0,0,0.08);
        }}
        .risk-item.high {{
            border-color: #ff416c;
            background: linear-gradient(90deg, #fff5f5 0%, #fff 100%);
        }}
        .risk-item.medium {{
            border-color: #f7971e;
            background: linear-gradient(90deg, #fffaf0 0%, #fff 100%);
        }}
        .risk-item.low {{
            border-color: #56ab2f;
            background: linear-gradient(90deg, #f0fff4 0%, #fff 100%);
        }}
        .risk-item .level {{
            font-weight: bold;
            margin-right: 10px;
        }}
        .risk-item .type {{
            background: #e9ecef;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 0.85em;
            margin-right: 10px;
        }}
        .risk-item .count-badge {{
            background: #ff416c;
            color: #fff;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 0.85em;
            margin-right: 10px;
            font-weight: bold;
        }}
        .risk-item .method-badge {{
            background: #667eea;
            color: #fff;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 0.85em;
            margin-right: 10px;
        }}
        .risk-item .description {{
            color: #555;
        }}
        .no-risk {{
            text-align: center;
            padding: 40px;
            color: #28a745;
            font-size: 1.2em;
        }}
        .no-risk::before {{
            content: "✓";
            display: block;
            font-size: 3em;
            margin-bottom: 10px;
        }}
        .footer {{
            text-align: center;
            padding: 20px;
            background: #f8f9fa;
            color: #666;
            font-size: 0.9em;
        }}
        @media (max-width: 768px) {{
            .header {{
                padding: 20px;
            }}
            .header h1 {{
                font-size: 1.8em;
            }}
            .section {{
                padding: 15px;
            }}
            .stats-grid {{
                padding: 15px;
            }}
            th, td {{
                padding: 8px;
                font-size: 0.8em;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔐 SSH 审计报告</h1>
            <p class="subtitle">VPS SSH 登录安全审计分析</p>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="number">{days}</div>
                <div class="label">分析天数</div>
            </div>
            <div class="stat-card">
                <div class="number">{total_files}</div>
                <div class="label">处理文件数</div>
            </div>
            <div class="stat-card">
                <div class="number">{parsed_lines}</div>
                <div class="label">解析行数</div>
            </div>
            <div class="stat-card">
                <div class="number">{total_ips}</div>
                <div class="label">总 IP 数</div>
            </div>
            <div class="stat-card">
                <div class="number">{total_representative}</div>
                <div class="label">查询 IP 数</div>
            </div>
            <div class="stat-card">
                <div class="number">{total_private}</div>
                <div class="label">内网 IP 数</div>
            </div>
            <div class="stat-card">
                <div class="number">{threshold}</div>
                <div class="label">高频阈值</div>
            </div>
        </div>
        
        <div class="section">
            <h2 class="section-title">📋 最近 {days} 天登录记录</h2>
            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th>序号</th>
                            <th>时间</th>
                            <th>用户</th>
                            <th>IP 地址</th>
                            <th>认证方法</th>
                            <th>归属地</th>
                        </tr>
                    </thead>
                    <tbody>'''

    for idx, r in enumerate(sorted(recent_logs, key=lambda x: x["dt"]), 1):
        segment = get_ip_segment(r["ip"])
        geo_data = cache.get(segment, {})
        geo_str = format_geo_info(geo_data)
        method_class = "password" if r["method"] == "password" else ""
        html_content += f'''
                        <tr>
                            <td>{idx}</td>
                            <td>{r['date']}</td>
                            <td>{r['user']}</td>
                            <td><code>{r['ip']}</code></td>
                            <td>{r['method']}</td>
                            <td>{geo_str}</td>
                        </tr>'''

    html_content += '''
                    </tbody>
                </table>
            </div>
        </div>
        
        <div class="section">
            <h2 class="section-title">📊 历史 IP 统计</h2>
            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th>序号</th>
                            <th>IP 地址</th>
                            <th>登录次数</th>
                            <th>首次登录</th>
                            <th>最近登录</th>
                            <th>归属地</th>
                        </tr>
                    </thead>
                    <tbody>'''

    for idx, (ip, s) in enumerate(sorted(stats.items(), key=lambda x: x[1]["count"], reverse=True), 1):
        segment = get_ip_segment(ip)
        geo_data = cache.get(segment, {})
        geo_str = format_geo_info(geo_data)
        count_highlight = "color: #ff416c; font-weight: bold;" if s["count"] > threshold else ""
        html_content += f'''
                        <tr>
                            <td>{idx}</td>
                            <td><code>{ip}</code></td>
                            <td style="{count_highlight}">{s['count']}</td>
                            <td>{s['first']}</td>
                            <td>{s['last']}</td>
                            <td>{geo_str}</td>
                        </tr>'''

    html_content += '''
                    </tbody>
                </table>
            </div>
        </div>
        
        <div class="risk-section">'''

    high_count = sum(1 for r in risks if r["level"] == "HIGH")
    medium_count = sum(1 for r in risks if r["level"] == "MEDIUM")
    low_count = sum(1 for r in risks if r["level"] == "LOW")

    html_content += f'''
            <h2 class="section-title">⚠️ 风险提示</h2>
            <div class="risk-summary">
                <div class="risk-badge risk-high">
                    <span>🔴</span>
                    <span>高危: {high_count}</span>
                </div>
                <div class="risk-badge risk-medium">
                    <span>🟠</span>
                    <span>中危: {medium_count}</span>
                </div>
                <div class="risk-badge risk-low">
                    <span>🟢</span>
                    <span>低危: {low_count}</span>
                </div>
            </div>'''

    if not risks:
        html_content += '''
            <div class="no-risk">
                未检测到安全风险
            </div>'''
    else:
        for risk in risks:
            level_text = RISK_LEVELS.get(risk["level"], risk["level"])
            type_text = RISK_TYPES.get(risk["type"], risk["type"])
            level_class = risk["level"].lower()
            
            extra_info = ""
            if risk.get("count"):
                extra_info += f'<span class="count-badge">×{risk["count"]}</span>'
            if risk.get("methods"):
                methods_str = ", ".join(risk["methods"])
                extra_info += f'<span class="method-badge">{methods_str}</span>'
            
            html_content += f'''
            <div class="risk-item {level_class}">
                <span class="level">[{level_text}]</span>
                <span class="type">{type_text}</span>
                {extra_info}
                <span class="description">{risk['description']}</span>
            </div>'''

    html_content += f'''
        </div>
        
        <div class="footer">
            <p>报告生成时间: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")} | SSH 审计工具</p>
        </div>
    </div>
</body>
</html>'''

    if output_path is None:
        output_path = "ssh_audit_report.html"
    
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)
    
    return output_path

# ===== 主逻辑 =====

def main():
    start_time = time.time()
    
    print("=" * 50)
    print("       SSH 审计工具（Python版）")
    print("=" * 50)

    script_dir = get_app_dir()
    default_log_dir = os.path.join(script_dir, "authlog")

    log_dir = input(f"请输入 auth.log 所在目录 [默认: {default_log_dir}]: ").strip()
    if not log_dir:
        log_dir = default_log_dir

    days_input = input("分析最近多少天 [默认: 7]: ").strip()
    days = int(days_input) if days_input else 7

    threshold_input = input("高频IP阈值（登录次数超过此值为高频）[默认: 10]: ").strip()
    threshold = int(threshold_input) if threshold_input else 10

    enable_geo = input("是否查询IP归属地？(y/n) [默认: y]: ").lower()
    if enable_geo == "":
        enable_geo = "y"
    enable_geo = enable_geo == "y"

    cutoff = datetime.now() - timedelta(days=days)

    cache = load_cache()

    recent_logs = []
    stats = defaultdict(lambda: {"count":0, "first":None, "last":None})

    files = sorted([f for f in os.listdir(log_dir)
                     if f.startswith("auth.log") or f.endswith(".log")])
    total_files = len(files)

    print(f"\n{'─' * 50}")
    print(f"发现 {total_files} 个日志文件")
    print(f"{'─' * 50}\n")

    total_lines = 0
    parsed_lines = 0

    for idx, fname in enumerate(files, 1):
        path = os.path.join(log_dir, fname)
        print(f"[{idx}/{total_files}] 处理: {fname}")

        file_lines = 0
        with open_log(path) as f:
            for line in f:
                total_lines += 1
                file_lines += 1
                
                if file_lines % 10000 == 0:
                    print(f"    已读取 {file_lines} 行...", end='\r')

                parsed = parse_line(line)
                if not parsed:
                    continue

                parsed_lines += 1

                dt = parsed["dt"]
                ip = parsed["ip"]

                s = stats[ip]
                s["count"] += 1
                s["first"] = s["first"] or dt
                s["last"] = dt

                if dt >= cutoff:
                    recent_logs.append(parsed)
        
        print(f"    完成: {file_lines} 行")

    print(f"\n{'─' * 50}")
    print(f"解析统计: 总行数 {total_lines}, 有效解析 {parsed_lines} 行")
    print(f"{'─' * 50}\n")

    unique_ips = set([x["ip"] for x in recent_logs] + list(stats.keys()))
    total_ips = len(unique_ips)

    representative_ips, private_ips = get_representative_ips(unique_ips)
    total_representative = len(representative_ips)
    total_private = len(private_ips)

    print(f"IP 分析统计:")
    print(f"  - 总 IP 数: {total_ips}")
    print(f"  - 内网 IP: {total_private} (不查询)")
    print(f"  - 待查询 IP: {total_representative} (聚合后)")
    print()

    private_result = {"country": "", "region": "", "city": "", "org": "", "status": "private"}
    for ip in private_ips:
        segment = get_ip_segment(ip)
        cache[segment] = private_result
        if ip in cache:
            del cache[ip]

    if enable_geo and total_representative > 0:
        print(f"开始查询IP归属地...\n")
        queried_ips = 0
        for ip in representative_ips:
            queried_ips += 1
            if queried_ips % 5 == 0 or queried_ips == total_representative:
                print(f"    查询进度: {queried_ips}/{total_representative}", end='\r')
            get_ip_geo(ip, cache, enable_geo)
        print(f"\n    完成: {total_representative} 个代表性IP")
    elif not enable_geo:
        for ip in unique_ips:
            get_ip_geo(ip, cache, False)

    save_cache(cache)

    risks = detect_risks(recent_logs, stats, threshold)

    generate_html_report(recent_logs, stats, risks, cache, days, threshold, total_files, parsed_lines, total_ips, total_representative, total_private)

    elapsed_time = time.time() - start_time
    print(f"\n{'=' * 50}")
    print(f"✅ HTML报告生成: ssh_audit_report.html")
    print(f"⏱️  总耗时: {elapsed_time:.2f} 秒")
    print(f"{'=' * 50}")

# ===== 入口 =====

if __name__ == "__main__":
    main()