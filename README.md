# 🔒 Advanced Security Log analysis

language :
- [persian](/fa.md)
- [en](https://github.com/dadashzadeh/log-analyzer-cpanel)

[](https://www.python.org/)
[]()
[]()

A powerful and comprehensive tool for analyzing web server logs, identifying security threats, detecting fake bots, and generating professional security reports

## 📋 Table of Contents

- [Features](#-features)
- [Requirements](#-requirements)
- [Installation](#-installation)
- [Usage](#-usage)
- [Output Reports](#-output-reports)
- [Detectable Attack Patterns](#-detectable-attack-patterns)
- [Supported Bots](#-supported-bots)
- [Usage Examples](#-usage-examples)

## ✨ Features

### 🎯 Security analysis
- **Detection of 15+ types of security attacks** including SQL Injection, XSS, LFI/RFI, Command Injection
- **Risk scoring for IPs** with intelligent algorithms
- **Identification of suspicious patterns** in user behavior
- **Request rate analysis** and DDoS attack detection

### 🤖 Bot analysis
- **Detection of 30+ legitimate bots** (Google, Bing, OpenAI, Perplexity, Meta, etc.)
- **Fake bot identification** with DNS and IP range verification
- **Bot visit timeline analysis**
- **Bot behavior reports** and crawling patterns

### 📊 Advanced Reporting
- **Excel reports** with multiple sheets and charts
- **Interactive HTML reports** with beautiful timeline
- **JSON output** for integration with other tools
- **Firewall rules** for iptables, nginx, Apache, CSF

### 🔍 Special Features
- Support for **compressed files** (gz, zip)
- **Time filtering** for analyzing specific periods
- **Multi-threading** for fast processing
- Support for **WordPress** and **OpenCart** sites

## 📦 Requirements

### Python Requirements
```bash
pip install -r requirements.txt
```

`requirements.txt` contents:
```
pandas
numpy
openpyxl
requests
user-agents
dnspython
```

### IP Range Files (Optional but recommended)
For more accurate bot detection, download these files:

```bash
# Google bots
wget https://www.gstatic.com/ipranges/googlebot.json
wget https://www.gstatic.com/ipranges/special-crawlers.json
wget https://www.gstatic.com/ipranges/user-triggered-fetchers.json
wget https://www.gstatic.com/ipranges/user-triggered-fetchers-google.json
wget https://www.gstatic.com/ipranges/cloud.json

# Bing bot
wget https://www.bing.com/toolbox/bingbot.json

# OpenAI bots
wget https://openai.com/gptbot-ranges.json -O gptbot.json

# Perplexity bots
wget https://www.perplexity.ai/perplexitybot.json
wget https://www.perplexity.ai/perplexity-user.json

# ahrefs bots
wget https://api.ahrefs.com/v3/public/crawler-ip-ranges

# duckduckgo bots
wget https://duckduckgo.com/duckduckbot.json
```

## 💻 Installation

1. **Clone the repository:**
```bash
git clone https://github.com/dadashzadeh/log-analyzer-cpanel.git
cd log-analyzer-cpanel
```

2. **Install dependencies:**
```bash
pip install -r requirements.txt
```

3. **Download IP Range files (optional):**
```bash
chmod +x download_ip_ranges.sh
./download_ip_ranges.sh
```

## 🚀 Usage

### Basic Usage
```bash
python log.py access_log.gz
```

### With Site Type Specification
```bash
python log.py access_log.gz --type wordpress
```

### With Time Filter
```bash
python log.py access_log.gz --period 30  # Analyze last 30 days
```

### Interactive Mode
```bash
python log.py access_log.gz --interactive
```

### Generate All Reports
```bash
python log.py access_log.gz --all
```

## 📊 Output Reports

### 1. **security_report.xlsx**
Comprehensive Excel report with sheets:
- **Overview**: Statistical summary
- **Risk Analysis**: IP risk analysis
- **Critical IPs**: Critical IP addresses
- **Attack Patterns**: Attack patterns
- **Bot Analysis**: Bot analysis
- **Bot Statistics**: Bot statistics
- **Temporal Analysis**: Temporal analysis
- **User Agents**: User-Agent analysis

### 2. **bot_timeline_report.html**
Beautiful HTML report including:
- Complete bot visit timeline
- Hourly activity charts
- AI bot and search engine statistics
- Most visited pages per bot

### 3. **security_report.json**
JSON report for:
- SIEM integration
- Automated processing
- API integrations

### 4. **Firewall Rules**
- `iptables_rules.sh`: Linux firewall rules
- `htaccess_rules.txt`: Apache rules
- `nginx_rules.conf`: Nginx configuration
- `csf_deny.txt`: CSF list
- `fail2ban_jail.conf`: Fail2ban configuration

### 5. **Ban Lists**
- `ban_list.txt`: All suspicious IPs
- `critical_ips.txt`: Critical IPs

## 🎯 Detectable Attack Patterns

| Attack Type | Risk Level | Description |
|------------|------------|-------------|
| **SQL Injection** | CRITICAL | SQL code injection |
| **XSS** | HIGH | Cross-Site Scripting |
| **LFI/RFI** | CRITICAL | Local/Remote File Inclusion |
| **Command Injection** | CRITICAL | System command injection |
| **XXE** | HIGH | XML External Entity |
| **LDAP Injection** | MEDIUM | LDAP injection |
| **XPath Injection** | MEDIUM | XPath injection |
| **SSTI** | HIGH | Server-Side Template Injection |
| **Log4j (Log4Shell)** | CRITICAL | Log4j attack |
| **Directory Traversal** | HIGH | Directory access |
| **Authentication Bypass** | CRITICAL | Authentication bypass |
| **Scanner Detection** | MEDIUM | Scan tool detection |
| **WordPress Specific** | MEDIUM | WordPress-specific attacks |
| **OpenCart Specific** | MEDIUM | OpenCart-specific attacks |
| **Sensitive Files** | HIGH | Sensitive file access |

## 🤖 Supported Bots

### Search Engines
- Google (Googlebot, AdsBot, etc.)
- Bing (Bingbot, MSNBot)
- Yandex
- Baidu
- DuckDuckGo

### AI Bots
- OpenAI (GPTBot, ChatGPT-User)
- Perplexity (PerplexityBot, Perplexity-User)
- Cohere
- Mistral
- You.com

### Social Networks
- Meta (Facebook, Instagram)
- LinkedIn
- ByteDance (TikTok)

### SEO Tools
- Ahrefs
- SemRush
- Moz

## 💡 Usage Examples

### Example 1: WordPress site analysis for the last 30 days
```bash
python log.py /var/log/apache2/access_log.gz \
    --type wordpress \
    --period 30 \
    --excel \
    --firewall
```

### Example 2: Complete analysis with all reports
```bash
python log.py access.log \
    --type general \
    --all \
    --timeline
```

### Example 3: Quick analysis to identify fake bots
```bash
python log.py access_log.gz \
    --json \
    --quiet
```

### Example 4: Interactive mode for time range selection
```bash
python log.py logs.zip \
    --interactive \
    --type opencart \
    --all
```

## 📈 Sample Output

```
================================================================================
🔒 Advanced Security Log Analyzer v2.0
================================================================================
📁 File: access_log.gz
🌐 Site type: wordpress

📦 Extracting access_log.gz...
✅ Extracted: access_log
📖 Reading log file...
✅ Loading complete:
  • Total lines: 125,432
  • Parsed: 124,891
  • Loaded: 124,891

⚙️ Starting comprehensive security analysis...
  📊 Calculating risk scores...
  🤖 Analyzing bots...
    ⚡ Using Threading for fast bot analysis...
    ✅ Bot analysis completed in 3.2 seconds
  🎯 Analyzing attack patterns...
  ⏰ Temporal analysis...

================================================================================
📊 Advanced Security Analysis Report
================================================================================

#### 📋 Security Status Summary
------------------------------------------------------------
  • Total requests: 124,891
  • Unique IPs: 3,456
  • Suspicious IPs: 234 (6.8%)
  • Critical IPs: 12
  • Traffic volume: 1,245.67 MB
  • Error rate: 4.32%

#### 🚨 Critical Threats (Immediate Action Required)
------------------------------------------------------------
  🔴 192.168.1.100
     Risk score: 95
     Reasons: SQL Injection attempts, High error rate, Suspicious User-Agent

✅ All reports generated successfully
```
