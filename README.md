# 🔒 Advanced Security Log Analyzer

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

## 🛡️ توصیه‌های امنیتی

پس از اجرای ابزار، توصیه‌های امنیتی شخصی‌سازی شده دریافت خواهید کرد:
- نصب WAF/CDN
- به‌روزرسانی پلاگین‌ها
- تنظیمات فایروال
- محدودسازی Rate Limiting
- فعالسازی 2FA
