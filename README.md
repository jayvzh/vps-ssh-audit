# VPS SSH Audit

SSH 登录日志审计工具，用于分析服务器的 SSH 登录记录，检测潜在安全风险。

## 功能特性

### 核心功能

- 解析 SSH 成功登录日志（支持多种格式）
- 统计 IP 登录频率和时间
- 查询 IP 地理位置信息
- 检测安全风险：
  - root 用户登录（高危）
  - 密码认证登录（中危）
  - 高频登录 IP（低危）

### 智能优化

- **IP 段聚合查询**：同一 IP 段（如 1.2.3.x）只查询一次，结果共享
- **内网 IP 自动识别**：自动跳过内网 IP 的归属地查询
- **IPv6 支持**：完整支持 IPv4 和 IPv6 地址查询
- **IP 结果缓存**：避免重复查询，节省时间

### 报告输出

- **HTML 报告**：可视化报告，包含表格和风险高亮

## 快速开始

### Windows 用户

直接下载 `vps-ssh-audit.exe`，双击运行即可：

### Linux 用户

一键运行脚本：

```bash
curl -fsSL https://raw.githubusercontent.com/jayvzh/vps-ssh-audit/main/vps-ssh-audit.sh | bash
```

## Windows用户如何获取日志文件

根据你的系统日志管理方式，选择对应的方法：

### 方式一：rsyslog/syslog（传统方式）

大多数 Linux 发行版默认使用 rsyslog，日志文件通常位于 `/var/log/auth.log`。

```bash
# 复制日志文件到当前目录
cp /var/log/auth.log* ./
```

### 方式二：systemd-journald

部分系统（如 Arch Linux、CoreOS）使用 systemd-journald 管理日志。

```bash
# 导出 SSH 成功登录日志
sudo journalctl -u ssh --grep="Accepted" -o short-iso > ssh_success.log
```

### 支持的日志格式

工具自动识别以下格式：

| 格式 | 示例 | 来源 |
| --- | --- | --- |
| 传统 syslog | `Sep 22 20:58:07 host sshd[123]: Accepted...` | rsyslog 默认 |
| ISO 8601 | `2024-09-22T20:58:07+08:00 host sshd[123]: Accepted...` | Debian 12+ |
| journalctl short-iso | `2024-09-22T20:58:07+0800 host sshd[123]: Accepted...` | systemd-journald |

## 输出文件

### ssh_audit_report.html

可视化 HTML 报告，包含：

- 统计概览卡片
- 登录记录表格
- IP 统计表格（高频 IP 高亮）
- 风险提示区域（颜色标记）

## 风险等级说明

| 等级 | 类型 | 说明 |
| --- | --- | --- |
| 高危 | Root 登录 | root 用户直接登录服务器 |
| 中危 | 密码认证 | 使用密码而非密钥认证 |
| 低危 | 高频 IP | 同一 IP 登录次数超过阈值 |

## 开发说明

### 环境要求

- Python 3.8+
- pip

### 安装依赖

```bash
pip install -r requirements.txt
```

### 运行

```bash
# GUI 版本
python gui.py

# 命令行版本
python main.py
```

### 打包 EXE

```bash
# 安装打包工具
pip install pyinstaller

# 打包 GUI 版本
pyinstaller --onefile --windowed --name "vps-ssh-audit" --distpath release --clean gui.py
```

## 项目结构

```
vps-ssh-audit/
├── gui.py              # GUI 界面程序
├── main.py             # 核心逻辑模块
├── vps-ssh-audit.sh    # Linux Shell 脚本
├── requirements.txt    # Python 依赖
└── release/            # 打包输出目录
    └── vps-ssh-audit.exe
```

## 注意事项

- IP 查询使用免费 API，有请求频率限制
- 日志时间解析默认使用当前年份，跨年日志自动推断
- 建议定期运行以监控服务器安全状态

## License

MIT License
