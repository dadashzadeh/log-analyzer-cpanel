# # 🔒 Advanced Security Log Analyzer

language :
- [persian](https://github.com/dadashzadeh/log-analyzer-cpanel/fa.md)
- [en](https://github.com/dadashzadeh/log-analyzer-cpanel)


[](https://www.python.org/)
[]()
[]()

یک ابزار قدرتمند و جامع برای تحلیل لاگ‌های وب سرور، شناسایی تهدیدات امنیتی، تشخیص بات‌های جعلی و تولید گزارش‌های امنیتی حرفه‌ای

## 📋 فهرست مطالب

- [ویژگی‌ها](#-ویژگیها)
- [نیازمندی‌ها](#-نیازمندیها)
- [نصب](#-نصب)
- [استفاده](#-استفاده)
- [گزارش‌های خروجی](#-گزارشهای-خروجی)
- [الگوهای حملات](#-الگوهای-حملات-قابل-تشخیص)
- [بات‌های پشتیبانی شده](#-باتهای-پشتیبانی-شده)
- [مثال‌های کاربردی](#-مثالهای-کاربردی)

## ✨ ویژگی‌ها

### 🎯 تحلیل امنیتی
- **تشخیص 15+ نوع حمله امنیتی** شامل SQL Injection, XSS, LFI/RFI, Command Injection
- **امتیازدهی ریسک به IP ها** با الگوریتم هوشمند
- **شناسایی الگوهای مشکوک** در رفتار کاربران
- **تحلیل نرخ درخواست** و تشخیص حملات DDoS

### 🤖 تحلیل بات‌ها
- **تشخیص 30+ بات معتبر** (Google, Bing, OpenAI, Perplexity, Meta, etc.)
- **شناسایی بات‌های جعلی** با DNS و IP range verification
- **تحلیل Timeline بازدید بات‌ها** 
- **گزارش رفتار بات‌ها** و الگوهای crawling

### 📊 گزارش‌دهی پیشرفته
- **گزارش Excel** با چندین sheet و نمودار
- **گزارش HTML** تعاملی با Timeline زیبا
- **خروجی JSON** برای یکپارچه‌سازی با سایر ابزارها
- **قوانین فایروال** برای iptables, nginx, Apache, CSF

### 🔍 قابلیت‌های ویژه
- پشتیبانی از **فایل‌های فشرده** (gz, zip)
- **فیلتر زمانی** برای تحلیل دوره‌های خاص
- **Multi-threading** برای پردازش سریع
- پشتیبانی از سایت‌های **WordPress** و **OpenCart**

## 📦 نیازمندی‌ها

### نیازمندی‌های Python
```bash
pip install -r requirements.txt
```

محتوای `requirements.txt`:
```
pandas
numpy
openpyxl
requests
user-agents
dnspython
```

### فایل‌های IP Range (اختیاری اما توصیه می‌شود)
برای تشخیص دقیق‌تر بات‌ها، این فایل‌ها را دانلود کنید:

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
```

## 💻 نصب

1. **کلون کردن مخزن:**
```bash
git clone https://github.com/dadashzadeh/log-analyzer-cpanel.git
cd log-analyzer-cpanel
```

2. **نصب وابستگی‌ها:**
```bash
pip install -r requirements.txt
```

3. **دانلود فایل‌های IP Range (اختیاری):**
```bash
chmod +x download_ip_ranges.sh
./download_ip_ranges.sh
```

## 🚀 استفاده

### استفاده پایه
```bash
python log.py access_log.gz
```

### با تعیین نوع سایت
```bash
python log.py access_log.gz --type wordpress
```

### با فیلتر زمانی
```bash
python log.py access_log.gz --period 30  # آنالیز 30 روز اخیر
```

### حالت تعاملی
```bash
python log.py access_log.gz --interactive
```

### تولید همه گزارش‌ها
```bash
python log.py access_log.gz --all
```

## 📊 گزارش‌های خروجی

### 1. **security_report.xlsx**
گزارش Excel جامع با sheet های:
- **Overview**: خلاصه آماری
- **Risk Analysis**: تحلیل ریسک IP ها
- **Critical IPs**: IP های بحرانی
- **Attack Patterns**: الگوهای حملات
- **Bot Analysis**: تحلیل بات‌ها
- **Bot Statistics**: آمار بات‌ها
- **Temporal Analysis**: تحلیل زمانی
- **User Agents**: تحلیل User-Agent ها

### 2. **bot_timeline_report.html**
گزارش HTML زیبا شامل:
- Timeline کامل بازدید بات‌ها
- نمودارهای فعالیت ساعتی
- آمار بات‌های AI و موتورهای جستجو
- صفحات پربازدید هر بات

### 3. **security_report.json**
گزارش JSON برای:
- یکپارچه‌سازی با SIEM
- پردازش‌های اتوماتیک
- API integrations

### 4. **قوانین فایروال**
- `iptables_rules.sh`: قوانین Linux firewall
- `htaccess_rules.txt`: قوانین Apache
- `nginx_rules.conf`: تنظیمات Nginx
- `csf_deny.txt`: لیست CSF
- `fail2ban_jail.conf`: تنظیمات Fail2ban

### 5. **لیست‌های Ban**
- `ban_list.txt`: همه IP های مشکوک
- `critical_ips.txt`: IP های بحرانی

## 🎯 الگوهای حملات قابل تشخیص

| نوع حمله | سطح خطر | توضیحات |
|----------|----------|----------|
| **SQL Injection** | CRITICAL | تزریق کد SQL |
| **XSS** | HIGH | Cross-Site Scripting |
| **LFI/RFI** | CRITICAL | Local/Remote File Inclusion |
| **Command Injection** | CRITICAL | تزریق دستورات سیستمی |
| **XXE** | HIGH | XML External Entity |
| **LDAP Injection** | MEDIUM | تزریق LDAP |
| **XPath Injection** | MEDIUM | تزریق XPath |
| **SSTI** | HIGH | Server-Side Template Injection |
| **Log4j (Log4Shell)** | CRITICAL | حمله Log4j |
| **Directory Traversal** | HIGH | دسترسی به دایرکتوری‌ها |
| **Authentication Bypass** | CRITICAL | دور زدن احراز هویت |
| **Scanner Detection** | MEDIUM | تشخیص ابزارهای اسکن |
| **WordPress Specific** | MEDIUM | حملات مخصوص WordPress |
| **OpenCart Specific** | MEDIUM | حملات مخصوص OpenCart |
| **Sensitive Files** | HIGH | دسترسی به فایل‌های حساس |

## 🤖 بات‌های پشتیبانی شده

### موتورهای جستجو
- Google (Googlebot, AdsBot, etc.)
- Bing (Bingbot, MSNBot)
- Yandex
- Baidu
- DuckDuckGo

### بات‌های AI
- OpenAI (GPTBot, ChatGPT-User)
- Perplexity (PerplexityBot, Perplexity-User)
- Cohere
- Mistral
- You.com

### شبکه‌های اجتماعی
- Meta (Facebook, Instagram)
- LinkedIn
- ByteDance (TikTok)

### ابزارهای SEO
- Ahrefs
- SemRush
- Moz

## 💡 مثال‌های کاربردی

### مثال 1: تحلیل سایت WordPress در 30 روز اخیر
```bash
python log.py /var/log/apache2/access_log.gz \
    --type wordpress \
    --period 30 \
    --excel \
    --firewall
```

### مثال 2: تحلیل کامل با همه گزارش‌ها
```bash
python log.py access.log \
    --type general \
    --all \
    --timeline
```

### مثال 3: تحلیل سریع برای شناسایی بات‌های جعلی
```bash
python log.py access_log.gz \
    --json \
    --quiet
```

### مثال 4: حالت تعاملی برای انتخاب بازه زمانی
```bash
python log.py logs.zip \
    --interactive \
    --type opencart \
    --all
```

## 📈 نمونه خروجی

```
================================================================================
🔒 Advanced Security Log Analyzer v2.0
================================================================================
📁 فایل: access_log.gz
🌐 نوع سایت: wordpress

📦 استخراج access_log.gz...
✅ استخراج شد: access_log
📖 خواندن فایل لاگ...
✅ بارگذاری کامل:
  • کل خطوط: 125,432
  • پارس شده: 124,891
  • بارگذاری شده: 124,891

⚙️ شروع تحلیل جامع امنیتی...
  📊 محاسبه امتیاز ریسک...
  🤖 تحلیل بات‌ها...
    ⚡ استفاده از Threading برای تحلیل سریع بات‌ها...
    ✅ تحلیل بات‌ها کامل شد در 3.2 ثانیه
  🎯 تحلیل الگوهای حمله...
  ⏰ تحلیل زمانی...

================================================================================
📊 گزارش تحلیل امنیتی پیشرفته
================================================================================

#### 📋 خلاصه وضعیت امنیتی
------------------------------------------------------------
  • کل درخواست‌ها: 124,891
  • IP های یکتا: 3,456
  • IP های مشکوک: 234 (6.8%)
  • IP های بحرانی: 12
  • حجم ترافیک: 1,245.67 MB
  • نرخ خطا: 4.32%

#### 🚨 تهدیدات بحرانی (نیاز به اقدام فوری)
------------------------------------------------------------
  🔴 192.168.1.100
     امتیاز ریسک: 95
     دلایل: SQL Injection attempts, High error rate, Suspicious User-Agent

✅ همه گزارش‌ها با موفقیت تولید شدند
```


به اینگلیسی تبدیل کن .md

# 🔒 Advanced Security Log Analyzer

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

### 🎯 Security Analysis
- **Detection of 15+ types of security attacks** including SQL Injection, XSS, LFI/RFI, Command Injection
- **Risk scoring for IPs** with intelligent algorithms
- **Identification of suspicious patterns** in user behavior
- **Request rate analysis** and DDoS attack detection

### 🤖 Bot Analysis
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
