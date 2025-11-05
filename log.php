<?php
/**
 * Complete Bot Log Analyzer - Full Version with All Features
 * نسخه کامل با تمام امکانات تحلیل بات + کاربران عادی
 * 
 * Version: 5.0 ULTIMATE WITH NON-BOT SUPPORT
 * Features:
 * - Complete Charts (Pie, Bar, Line, Timeline) - با فیلتر log_type
 * - Advanced Filtering System (Bot + Non-Bot)
 * - Detailed Bot Statistics with IP Range Verification
 * - Non-Bot User Tracking (Browser/Device Detection)
 * - Interactive Timeline with Full Details
 * - Export to Excel (Both Bot & Non-Bot)
 * - Real-time Search and Filter
 * - php 7+
 */

error_reporting(E_ALL);
ini_set('display_errors', 1);
ini_set('memory_limit', '2048M');
ini_set('max_execution_time', 900);
set_time_limit(900);
date_default_timezone_set('Asia/Tehran');

ob_start();

// ==============================================================
// IP Range Manager Class
// ==============================================================
class IPRangeManager {
    private $ipRanges = [];
    private $ipListsDir = 'iplists';
    private $loadedFiles = [];
    private $ipCache = [];
    
    public function __construct($ipListsDir = 'iplists') {
        $this->ipListsDir = $ipListsDir;
        $this->loadAllIPRanges();
    }
    
    private function loadAllIPRanges() {
        $jsonFiles = [
            'Google' => ['googlebot.json', 'special-crawlers.json', 'user-triggered-fetchers.json', 'user-triggered-fetchers-google.json'],
            'Bing' => ['bingbot.json'],
            'OpenAI' => array('gptbot.json', 'searchbot.json', 'chatgpt-user.json'),
            'PerplexityBot' => ['perplexitybot.json'],
            'PerplexityUser' => ['perplexity-user.json'],
            'GoogleCloud' => ['cloud.json'],
            'DuckDuckGo' => ['duckduckbot.json'],
            'Ahrefs' => ['ahrefs-crawler-ip-ranges.json'],
        ];
        
        foreach ($jsonFiles as $botName => $files) {
            $this->ipRanges[$botName] = [];
            
            foreach ($files as $filename) {
                $filepath = $this->ipListsDir . '/' . $filename;
                
                if (file_exists($filepath)) {
                    try {
                        $jsonData = json_decode(file_get_contents($filepath), true);
                        
                        if (isset($jsonData['prefixes']) && is_array($jsonData['prefixes'])) {
                            foreach ($jsonData['prefixes'] as $prefix) {
                                if (isset($prefix['ipv4Prefix'])) {
                                    $this->ipRanges[$botName][] = $prefix['ipv4Prefix'];
                                } elseif (isset($prefix['ipv6Prefix'])) {
                                    $this->ipRanges[$botName][] = $prefix['ipv6Prefix'];
                                }
                            }
                        }
                        
                        $this->loadedFiles[] = $filename;
                    } catch (Exception $e) {
                        error_log("Error loading $filename: " . $e->getMessage());
                    }
                }
            }
        }
    }
    
    public function isIPInRange($ip, $botName) {
        $cacheKey = $ip . ':' . $botName;
        if (isset($this->ipCache[$cacheKey])) {
            return $this->ipCache[$cacheKey];
        }
        
        $result = false;
        
        if (!isset($this->ipRanges[$botName])) {
            return $result;
        }
        
        foreach ($this->ipRanges[$botName] as $range) {
            if ($this->ipInRange($ip, $range)) {
                $result = true;
                break;
            }
        }
        
        $this->ipCache[$cacheKey] = $result;
        return $result;
    }
    
    private function ipInRange($ip, $range) {
        if (strpos($range, '/') === false) {
            return $ip === $range;
        }
        
        list($subnet, $bits) = explode('/', $range);
        
        if (strpos($ip, ':') !== false || strpos($subnet, ':') !== false) {
            return $this->ipv6InRange($ip, $range);
        }
        
        $ip_long = ip2long($ip);
        $subnet_long = ip2long($subnet);
        
        if ($ip_long === false || $subnet_long === false) {
            return false;
        }
        
        $mask = -1 << (32 - (int)$bits);
        $subnet_long &= $mask;
        
        return ($ip_long & $mask) == $subnet_long;
    }
    
    private function ipv6InRange($ip, $range) {
        list($subnet, $bits) = explode('/', $range);
        
        $ip_binary = @inet_pton($ip);
        $subnet_binary = @inet_pton($subnet);
        
        if ($ip_binary === false || $subnet_binary === false) {
            return false;
        }
        
        $full_bytes = floor($bits / 8);
        $remaining_bits = $bits % 8;
        
        for ($i = 0; $i < $full_bytes; $i++) {
            if ($ip_binary[$i] !== $subnet_binary[$i]) {
                return false;
            }
        }
        
        if ($remaining_bits > 0) {
            $mask = 0xFF << (8 - $remaining_bits);
            if ((ord($ip_binary[$full_bytes]) & $mask) !== (ord($subnet_binary[$full_bytes]) & $mask)) {
                return false;
            }
        }
        
        return true;
    }
    
    public function getTotalRanges() {
        $total = 0;
        foreach ($this->ipRanges as $ranges) {
            $total += count($ranges);
        }
        return $total;
    }
    
    public function getLoadedFiles() {
        return $this->loadedFiles;
    }
} 

// ==============================================================
// Bot Log Analyzer Class
// ==============================================================
class BotLogAnalyzer {
    
    private $logFile;
    private $logs = [];
    private $botStats = [];
    private $nonBotLogs = [];
    private $nonBotStats = [];
    private $ipRangeManager;
    public $extractedFiles = [];
    private $tempDir = 'temp_extracted_logs';
    private $sessionId;
    
    private $legitimateBots = [
        'Google' => [
            'patterns' => ['googlebot', 'adsbot-google', 'mediapartners-google', 'google-inspectiontool', 'googleother', 'google-extended', 'feedfetcher-google'],
            'icon' => '🔍',
            'color' => '#4285F4'
        ],
        'Bing' => [
            'patterns' => ['bingbot', 'msnbot', 'bingpreview'],
            'icon' => '🔎',
            'color' => '#00BCF2'
        ],
        'OpenAI' => [
            'patterns' => ['gptbot', 'oai-searchbot', 'chatgpt-user', 'chatgpt'],
            'icon' => '🤖',
            'color' => '#10A37F'
        ],
        'ClaudeAI' => [
            'patterns' => ['ClaudeBot'],
            'icon' => '🤖',
            'color' => '#10A37F'
        ],
        'PerplexityBot' => [
            'patterns' => ['perplexitybot', 'perplexity'],
            'icon' => '🧠',
            'color' => '#8B5CF6'
        ],
        'PerplexityUser' => [
            'patterns' => ['perplexity-user'],
            'icon' => '👤',
            'color' => '#9333EA'
        ],
        'Meta' => [
            'patterns' => ['facebookbot', 'facebookexternalhit', 'meta-externalagent', 'facebookcatalog'],
            'icon' => '📘',
            'color' => '#1877F2'
        ],
        'WordPress' => [
            'patterns' => ['wordpress', 'wp-cron', 'jetpack'],
            'icon' => '📝',
            'color' => '#21759B'
        ],
        'LinkedIn' => [
            'patterns' => ['linkedinbot'],
            'icon' => '💼',
            'color' => '#0A66C2'
        ],
        'ByteDance' => [
            'patterns' => ['bytespider', 'tiktokbot'],
            'icon' => '🎵',
            'color' => '#000000'
        ],
        'DuckDuckGo' => [
            'patterns' => ['duckduckbot', 'duckassistbot'],
            'icon' => '🦆',
            'color' => '#DE5833'
        ],
        'Yandex' => [
            'patterns' => ['yandexbot', 'yandex'],
            'icon' => '🇷🇺',
            'color' => '#FF0000'
        ],
        'Baidu' => [
            'patterns' => ['baiduspider'],
            'icon' => '🇨🇳',
            'color' => '#2319DC'
        ],
        'Amazon' => [
            'patterns' => ['amazonbot'],
            'icon' => '🛒',
            'color' => '#FF9900'
        ],
        'Apple' => [
            'patterns' => ['applebot'],
            'icon' => '🍎',
            'color' => '#555555'
        ],
        'Ahrefs' => [
            'patterns' => ['ahrefsbot'],
            'icon' => '🔗',
            'color' => '#FF6600'
        ],
        'SemRush' => [
            'patterns' => ['semrushbot'],
            'icon' => '📈',
            'color' => '#FF642D'
        ],
        'Chrome-Lighthouse' => [
            'patterns' => ['chrome-lighthouse', 'lighthouse'],
            'icon' => '🔦',
            'color' => '#F44B21'
        ],
        'Pingdom' => [
            'patterns' => ['pingdom', 'uptimerobot', 'statuscake', 'monitor'],
            'icon' => '⏱️',
            'color' => '#FFC600'
        ],
        'Slack' => [
            'patterns' => ['slackbot', 'slack-imgproxy'],
            'icon' => '💬',
            'color' => '#4A154B'
        ],
        'Discord' => [
            'patterns' => ['discordbot', 'discord'],
            'icon' => '🎮',
            'color' => '#5865F2'
        ],
        'Telegram' => [
            'patterns' => ['telegrambot', 'telegram'],
            'icon' => '✈️',
            'color' => '#0088CC'
        ],
        'WhatsApp' => [
            'patterns' => ['whatsapp'],
            'icon' => '💚',
            'color' => '#25D366'
        ],
        'Twitter' => [
            'patterns' => ['twitterbot', 'twitter'],
            'icon' => '🐦',
            'color' => '#1DA1F2'
        ],
        'GoogleCloud' => [
            'patterns' => [],
            'icon' => '☁️',
            'color' => '#4285F4'
        ]
    ];
    
    
    public function __construct($logFile = null) {
        $this->sessionId = uniqid('log_', true);
        $this->tempDir = 'temp_extracted_logs_' . substr($this->sessionId, 0, 10);
        
        if (!is_dir($this->tempDir)) {
            if (!@mkdir($this->tempDir, 0755, true)) {
                throw new Exception("خطا در ایجاد پوشه موقت: " . $this->tempDir);
            }
        }
        
        $this->ipRangeManager = new IPRangeManager();
        
        if ($logFile === null) {
            $this->logFile = $this->findCPanelLogFile();
        } else {
            $this->logFile = $logFile;
        }
    }
    
    private function findCPanelLogFile() {
        $domain = $_SERVER['HTTP_HOST'];
        $currentMonth = date('M-Y');

        $possiblePaths = [
            "logs/{$domain}-ssl_log-{$currentMonth}.gz",
            "logs/{$domain}-ssl_log.gz",
            "logs/{$domain}-ssl_log",
            "/logs/{$domain}-{$currentMonth}.gz",
            "/logs/{$domain}.gz",
            "/logs/{$domain}",
            "/home/" . get_current_user() . "/logs/{$domain}-ssl_log-{$currentMonth}.gz",
            "/home/" . get_current_user() . "/logs/{$domain}-ssl_log.gz",
            "/home/" . get_current_user() . "/logs/{$domain}",
            "/home/" . get_current_user() . "/logs/{$domain}.gz",
            $_SERVER['DOCUMENT_ROOT'] . "/../logs/{$domain}",
            $_SERVER['DOCUMENT_ROOT'] . "/../logs/{$domain}.gz",
        ];
        
        foreach ($possiblePaths as $path) {
            if (file_exists($path) && is_readable($path)) {
                echo "<div class='alert alert-success'>✅ فایل لاگ یافت شد: <code>" . htmlspecialchars($path) . "</code></div>";
                flush();
                ob_flush();
                return $path;
            }
        }
        
        $logsDir = '/logs';
        if (is_dir($logsDir) && is_readable($logsDir)) {
            echo "<div class='alert alert-info'>🔍 جستجو در پوشه /logs/...</div>";
            flush();
            ob_flush();
            
            $sslPattern = $logsDir . '/' . $domain . '-ssl_log*.gz';
            $sslFiles = glob($sslPattern);
            
            if (!empty($sslFiles)) {
                usort($sslFiles, function($a, $b) {
                    return filemtime($b) - filemtime($a);
                });
                
                echo "<div class='alert alert-success'>✅ فایل SSL یافت شد: <code>" . htmlspecialchars($sslFiles[0]) . "</code></div>";
                flush();
                ob_flush();
                return $sslFiles[0];
            }
            
            $pattern = $logsDir . '/' . $domain . '*.gz';
            $files = glob($pattern);
            
            if (!empty($files)) {
                usort($files, function($a, $b) {
                    return filemtime($b) - filemtime($a);
                });
                
                echo "<div class='alert alert-success'>✅ فایل لاگ یافت شد: <code>" . htmlspecialchars($files[0]) . "</code></div>";
                flush();
                ob_flush();
                return $files[0];
            }
        }
        
        echo "<div class='alert alert-danger'>❌ هیچ فایل لاگی یافت نشد!</div>";
        flush();
        ob_flush();
        
        return null;
    }
    
    private function extractFile($filePath) {
        if (!file_exists($filePath)) {
            throw new Exception("فایل یافت نشد: " . $filePath);
        }
        
        $extractedFiles = [];
        $ext = strtolower(pathinfo($filePath, PATHINFO_EXTENSION));
        
        if ($ext === 'gz') {
            $outputFile = $this->tempDir . '/' . basename($filePath, '.gz');
            
            $gz = @gzopen($filePath, 'rb');
            if (!$gz) {
                throw new Exception("خطا در باز کردن فایل فشرده");
            }
            
            $out = @fopen($outputFile, 'wb');
            if (!$out) {
                @gzclose($gz);
                throw new Exception("خطا در ایجاد فایل خروجی");
            }
            
            while (!gzeof($gz)) {
                $data = gzread($gz, 8192);
                if ($data === false) break;
                fwrite($out, $data);
            }
            
            fclose($out);
            gzclose($gz);
            
            $extractedFiles[] = $outputFile;
            $this->extractedFiles[] = $outputFile;
        } else {
            $extractedFiles[] = $filePath;
        }
        
        return $extractedFiles;
    }
    
    public function cleanup() {
        $deletedCount = 0;
        
        if (is_array($this->extractedFiles)) {
            foreach ($this->extractedFiles as $file) {
                if (file_exists($file) && is_file($file)) {
                    if (@unlink($file)) {
                        $deletedCount++;
                    }
                }
            }
        }
        
        if (is_dir($this->tempDir)) {
            $files = @scandir($this->tempDir);
            
            if ($files !== false && is_array($files)) {
                $files = array_diff($files, ['.', '..']);
                
                if (count($files) === 0) {
                    @rmdir($this->tempDir);
                }
            }
        }
        
        return $deletedCount;
    }
    
    public function loadLogs($limit = 10000, $daysBack = 1) {
        if (!$this->logFile || !file_exists($this->logFile)) {
            throw new Exception("فایل لاگ یافت نشد");
        }
        
        if ($daysBack == 1) {
            $cutoffDate = strtotime('today', time());
        } else {
            $cutoffDate = strtotime("-{$daysBack} days", strtotime('today', time()));
        }
        
        $files = $this->extractFile($this->logFile);
        
        $this->logs = [];
        $this->nonBotLogs = [];
        $lineCount = 0;
        $totalLines = 0;
        
        foreach ($files as $file) {
            $handle = @fopen($file, 'r');
            if (!$handle) continue;
            
            while (!feof($handle) && $lineCount < $limit) {
                $line = fgets($handle, 8192);
                if ($line === false) break;
                
                $totalLines++;
                
                $parsed = $this->parseLogLine(trim($line));
                
                if ($parsed && $parsed['timestamp'] >= $cutoffDate) {
                    $botInfo = $this->identifyBotWithIPRange($parsed['ip'], $parsed['user_agent']);
                    
                    if ($botInfo['is_bot']) {
                        $parsed['bot_name'] = $botInfo['bot_name'];
                        $parsed['bot_type'] = $botInfo['bot_type'];
                        $parsed['bot_icon'] = $botInfo['icon'];
                        $parsed['bot_color'] = $botInfo['color'];
                        $parsed['verification'] = $botInfo['verification'];
                        $parsed['ip_verified'] = $botInfo['ip_verified'];
                        
                        $this->logs[] = $parsed;
                        $lineCount++;
                    } else {
                        $parsed['is_bot'] = false;
                        $parsed['user_type'] = $this->identifyUserType($parsed['user_agent']);
                        
                        $this->nonBotLogs[] = $parsed;
                        $lineCount++;
                    }
                }
            }
            
            fclose($handle);
        }
        
        usort($this->logs, function($a, $b) {
            return $b['timestamp'] - $a['timestamp'];
        });
        
        usort($this->nonBotLogs, function($a, $b) {
            return $b['timestamp'] - $a['timestamp'];
        });
        
        $this->calculateStats();
        $this->calculateNonBotStats();
        
        return count($this->logs) + count($this->nonBotLogs);
    }
    
    private function identifyBotWithIPRange($ip, $userAgent) {
        $ua = strtolower($userAgent);
        
        foreach ($this->legitimateBots as $botName => $botInfo) {
            // GoogleCloud: فقط بر اساس IP شناسایی (بدون UA)
            if ($botName === 'GoogleCloud') {
                $ipVerified = $this->ipRangeManager->isIPInRange($ip, $botName);
                
                if ($ipVerified) {
                    return array(
                        'is_bot' => true,
                        'bot_name' => $botName,
                        'bot_type' => 'legitimate',
                        'icon' => $botInfo['icon'],
                        'color' => $botInfo['color'],
                        'verification' => '✅ IP تأیید',
                        'ip_verified' => true
                    );
                }
                
                // اگر IP تأیید نشد، به بات بعدی برو
                continue;
            }
            
            // سایر بات‌ها: چک UA
            $uaMatches = false;
            if (!empty($botInfo['patterns'])) {
                foreach ($botInfo['patterns'] as $pattern) {
                    if (strpos($ua, strtolower($pattern)) !== false) {
                        $uaMatches = true;
                        break;
                    }
                }
            }
            
            if (!$uaMatches) continue;
            
            $ipVerified = $this->ipRangeManager->isIPInRange($ip, $botName);
            
            if ($uaMatches || $ipVerified) {
                if ($uaMatches && $ipVerified) {
                    $verificationType = '✅ کامل';
                    $botType = 'legitimate';
                } elseif ($ipVerified) {
                    $verificationType = '✅ IP تأیید';
                    $botType = 'legitimate';
                } elseif ($uaMatches && !empty($botInfo['patterns'])) {
                    $verificationType = '⚠️ فقط UA';
                    $botType = 'potentially_legitimate';
                } else {
                    $verificationType = '❓ نامعلوم';
                    $botType = 'unknown';
                }
                
                return [
                    'is_bot' => true,
                    'bot_name' => $botName,
                    'bot_type' => $botType,
                    'icon' => $botInfo['icon'],
                    'color' => $botInfo['color'],
                    'verification' => $verificationType,
                    'ip_verified' => $ipVerified
                ];
            }
        }
        
        $suspiciousPatterns = ['bot', 'crawler', 'spider', 'scraper'];
        foreach ($suspiciousPatterns as $pattern) {
            if (strpos($ua, $pattern) !== false) {
                return [
                    'is_bot' => true,
                    'bot_name' => 'Unknown Bot',
                    'bot_type' => 'suspicious',
                    'icon' => '⚠️',
                    'color' => '#FF9800',
                    'verification' => '⚠️ مشکوک',
                    'ip_verified' => false
                ];
            }
        }
        
        return ['is_bot' => false];
    }
    
    private function identifyUserType($userAgent) {
        $ua = strtolower($userAgent);
        
        if (strpos($ua, 'chrome') !== false && strpos($ua, 'edg') === false && strpos($ua, 'opr') === false) {
            return ['type' => 'Chrome', 'icon' => '🌐', 'color' => '#4285F4'];
        } elseif (strpos($ua, 'firefox') !== false) {
            return ['type' => 'Firefox', 'icon' => '🦊', 'color' => '#FF7139'];
        } elseif (strpos($ua, 'safari') !== false && strpos($ua, 'chrome') === false) {
            return ['type' => 'Safari', 'icon' => '🧭', 'color' => '#00AAFF'];
        } elseif (strpos($ua, 'edg') !== false) {
            return ['type' => 'Edge', 'icon' => '🌊', 'color' => '#0078D7'];
        } elseif (strpos($ua, 'opr') !== false || strpos($ua, 'opera') !== false) {
            return ['type' => 'Opera', 'icon' => '🎭', 'color' => '#FF1B2D'];
        } elseif (strpos($ua, 'msie') !== false || strpos($ua, 'trident') !== false) {
            return ['type' => 'Internet Explorer', 'icon' => '🏛️', 'color' => '#0076D7'];
        }
        
        if (strpos($ua, 'mobile') !== false || strpos($ua, 'android') !== false) {
            return ['type' => 'Mobile', 'icon' => '📱', 'color' => '#34A853'];
        } elseif (strpos($ua, 'tablet') !== false || strpos($ua, 'ipad') !== false) {
            return ['type' => 'Tablet', 'icon' => '📱', 'color' => '#FBBC04'];
        }
        
        if (empty($ua) || $ua === '-') {
            return ['type' => 'Unknown', 'icon' => '❓', 'color' => '#9E9E9E'];
        }
        
        return ['type' => 'Desktop', 'icon' => '💻', 'color' => '#5F6368'];
    }
    
    private function parseLogLine($line) {
        $pattern = '/^(\S+) \S+ \S+ \[([^\]]+)\] "([^"]*)" (\d+) (\S+) "([^"]*)" "([^"]*)"/';
        
        if (preg_match($pattern, $line, $matches)) {
            $dateStr = $matches[2];
            $timestamp = strtotime(str_replace('/', '-', substr($dateStr, 0, 11)) . substr($dateStr, 12));
            
            $requestParts = explode(' ', $matches[3]);
            
            return [
                'ip' => $matches[1],
                'timestamp' => $timestamp,
                'datetime' => date('Y-m-d H:i:s', $timestamp),
                'date' => date('Y-m-d', $timestamp),
                'time' => date('H:i:s', $timestamp),
                'hour' => date('H', $timestamp),
                'request' => $matches[3],
                'method' => $requestParts[0] ?? 'GET',
                'url' => $requestParts[1] ?? '/',
                'status_code' => (int)$matches[4],
                'bytes' => $matches[5] !== '-' ? (int)$matches[5] : 0,
                'referrer' => $matches[6],
                'user_agent' => $matches[7]
            ];
        }
        
        return null;
    }
    
    private function calculateStats() {
        $this->botStats = [];
        
        foreach ($this->logs as $log) {
            $botName = $log['bot_name'];
            
            if (!isset($this->botStats[$botName])) {
                $this->botStats[$botName] = [
                    'name' => $botName,
                    'icon' => $log['bot_icon'],
                    'color' => $log['bot_color'],
                    'count' => 0,
                    'verified_count' => 0,
                    'ips' => [],
                    'urls' => [],
                    'status_codes' => [],
                    'methods' => [],
                    'hourly' => [],
                    'daily' => [],
                    'first_seen' => $log['timestamp'],
                    'last_seen' => $log['timestamp'],
                    'bandwidth' => 0
                ];
            }
            
            $this->botStats[$botName]['count']++;
            
            if ($log['ip_verified']) {
                $this->botStats[$botName]['verified_count']++;
            }
            
            $this->botStats[$botName]['ips'][$log['ip']] = ($this->botStats[$botName]['ips'][$log['ip']] ?? 0) + 1;
            $this->botStats[$botName]['urls'][$log['url']] = ($this->botStats[$botName]['urls'][$log['url']] ?? 0) + 1;
            $this->botStats[$botName]['status_codes'][$log['status_code']] = ($this->botStats[$botName]['status_codes'][$log['status_code']] ?? 0) + 1;
            $this->botStats[$botName]['methods'][$log['method']] = ($this->botStats[$botName]['methods'][$log['method']] ?? 0) + 1;
            $this->botStats[$botName]['hourly'][$log['hour']] = ($this->botStats[$botName]['hourly'][$log['hour']] ?? 0) + 1;
            $this->botStats[$botName]['daily'][$log['date']] = ($this->botStats[$botName]['daily'][$log['date']] ?? 0) + 1;
            $this->botStats[$botName]['bandwidth'] += $log['bytes'];
            
            if ($log['timestamp'] < $this->botStats[$botName]['first_seen']) {
                $this->botStats[$botName]['first_seen'] = $log['timestamp'];
            }
            if ($log['timestamp'] > $this->botStats[$botName]['last_seen']) {
                $this->botStats[$botName]['last_seen'] = $log['timestamp'];
            }
        }
        
        uasort($this->botStats, function($a, $b) {
            return $b['count'] - $a['count'];
        });
    }
    
    public function calculateNonBotStats() {
        $this->nonBotStats = [
            'total' => count($this->nonBotLogs),
            'unique_ips' => count(array_unique(array_column($this->nonBotLogs, 'ip'))),
            'unique_urls' => count(array_unique(array_column($this->nonBotLogs, 'url'))),
            'user_types' => [],
            'status_codes' => [],
            'hourly' => array_fill(0, 24, 0),
            'daily' => [],
            'bandwidth' => 0
        ];
        
        foreach ($this->nonBotLogs as $log) {
            $userType = $log['user_type']['type'];
            
            if (!isset($this->nonBotStats['user_types'][$userType])) {
                $this->nonBotStats['user_types'][$userType] = [
                    'count' => 0,
                    'icon' => $log['user_type']['icon'],
                    'color' => $log['user_type']['color']
                ];
            }
            
            $this->nonBotStats['user_types'][$userType]['count']++;
            $this->nonBotStats['status_codes'][$log['status_code']] = 
                ($this->nonBotStats['status_codes'][$log['status_code']] ?? 0) + 1;
            $this->nonBotStats['hourly'][(int)$log['hour']]++;
            $this->nonBotStats['daily'][$log['date']] = 
                ($this->nonBotStats['daily'][$log['date']] ?? 0) + 1;
            $this->nonBotStats['bandwidth'] += $log['bytes'];
        }
        
        return $this->nonBotStats;
    }
    
    public function getLogs() {
        return $this->logs;
    }
    
    public function getStats() {
        return $this->botStats;
    }
    
    public function getNonBotLogs() {
        return $this->nonBotLogs;
    }
    
    public function getNonBotStats() {
        return $this->nonBotStats;
    }
    
    public function getLogFile() {
        return $this->logFile;
    }
    
    public function getIPRangeManager() {
        return $this->ipRangeManager;
    }
    
    public static function formatBytes($bytes) {
        $units = ['B', 'KB', 'MB', 'GB', 'TB'];
        $i = 0;
        while ($bytes >= 1024 && $i < count($units) - 1) {
            $bytes /= 1024;
            $i++;
        }
        return round($bytes, 2) . ' ' . $units[$i];
    }
}

// پردازش
$analyzer = null;
$error = null;
$success = null;
$processingTime = 0;

$daysBack = isset($_GET['days']) ? (int)$_GET['days'] : 1;
$limit = isset($_GET['limit']) ? (int)$_GET['limit'] : 10000;
$botFilter = isset($_GET['bot']) ? $_GET['bot'] : 'all';
$statusFilter = isset($_GET['status']) ? $_GET['status'] : 'all';
$ipFilter = isset($_GET['ip_filter']) ? $_GET['ip_filter'] : '';
$urlFilter = isset($_GET['url_filter']) ? $_GET['url_filter'] : '';
$verificationFilter = isset($_GET['verification']) ? $_GET['verification'] : 'all';
$dateFilter = isset($_GET['date_filter']) ? $_GET['date_filter'] : '';
$autoCleanup = isset($_GET['auto_cleanup']) ? true : false;
$logTypeFilter = isset($_GET['log_type']) ? $_GET['log_type'] : 'all';

$currentPage = isset($_GET['page']) ? max(1, (int)$_GET['page']) : 1;
$perPage = isset($_GET['per_page']) ? (int)$_GET['per_page'] : 50;
$offset = ($currentPage - 1) * $perPage;

if (isset($_GET['cleanup']) && isset($_GET['confirm'])) {
    try {
        $analyzer = new BotLogAnalyzer();
        $deleted = $analyzer->cleanup();
        $success = "✅ پاکسازی: {$deleted} فایل";
    } catch (Exception $e) {
        $error = $e->getMessage();
    }
}

if (!isset($_GET['cleanup'])) {
    try {
        $startTime = microtime(true);
        
        $analyzer = new BotLogAnalyzer();
        
        if ($analyzer->getLogFile()) {
            $logCount = $analyzer->loadLogs($limit, $daysBack);
            
            $processingTime = microtime(true) - $startTime;
            
            $success = sprintf("✅ %s لاگ در %.2f ثانیه", number_format($logCount), $processingTime);
            
            if ($autoCleanup && !empty($analyzer->extractedFiles)) {
                $deleted = $analyzer->cleanup();
            }
        } else {
            $error = "⚠️ فایل لاگ یافت نشد";
        }
    } catch (Exception $e) {
        $error = $e->getMessage();
    }
}

if ($analyzer) {
    $logs = $analyzer->getLogs();
    $stats = $analyzer->getStats();
    $nonBotLogs = $analyzer->getNonBotLogs();
    $nonBotStats = $analyzer->getNonBotStats();
    
    if (!empty($logs)) {
        $filteredLogs = $logs;
        
        if ($botFilter !== 'all') {
            $filteredLogs = array_filter($filteredLogs, function($log) use ($botFilter) {
                return $log['bot_name'] === $botFilter;
            });
        }
        
        if ($statusFilter !== 'all') {
            $filteredLogs = array_filter($filteredLogs, function($log) use ($statusFilter) {
                if ($statusFilter === '200') return $log['status_code'] == 200;
                if ($statusFilter === '404') return $log['status_code'] == 404;
                if ($statusFilter === '4xx') return $log['status_code'] >= 400 && $log['status_code'] < 500;
                if ($statusFilter === '5xx') return $log['status_code'] >= 500;
                return true;
            });
        }
        
        if ($verificationFilter !== 'all') {
            $filteredLogs = array_filter($filteredLogs, function($log) use ($verificationFilter) {
                if ($verificationFilter === 'verified') return $log['ip_verified'] === true;
                if ($verificationFilter === 'unverified') return $log['ip_verified'] === false;
                return true;
            });
        }
        
        if (!empty($ipFilter)) {
            $filteredLogs = array_filter($filteredLogs, function($log) use ($ipFilter) {
                return strpos($log['ip'], $ipFilter) !== false;
            });
        }
        
        if (!empty($urlFilter)) {
            $filteredLogs = array_filter($filteredLogs, function($log) use ($urlFilter) {
                return stripos($log['url'], $urlFilter) !== false;
            });
        }
        
        if (!empty($dateFilter)) {
            $filteredLogs = array_filter($filteredLogs, function($log) use ($dateFilter) {
                return strpos($log['date'], $dateFilter) !== false;
            });
        }
        
        $logs = array_values($filteredLogs);
        
        $totalLogs = count($logs);
        $totalPages = ceil($totalLogs / $perPage);
        $currentPage = min($currentPage, max(1, $totalPages));
        $paginatedLogs = array_slice($logs, $offset, $perPage);
    }
}
?>
<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>تحلیلگر کامل لاگ بات‌ها + کاربران - Ultimate Edition V5</title>
    
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.rtl.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.0/font/bootstrap-icons.css" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    
    <style>
        :root {
            --primary: #667eea;
            --secondary: #764ba2;
            --success: #10B981;
            --danger: #EF4444;
            --warning: #F59E0B;
            --info: #3B82F6;
            --dark: #1F2937;
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, var(--primary) 0%, var(--secondary) 100%);
            min-height: 100vh;
            padding: 20px 0;
        }
        
        .main-container {
            max-width: 1800px;
            margin: 0 auto;
        }
        
        .page-header {
            background: white;
            border-radius: 20px;
            padding: 30px;
            margin-bottom: 30px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            text-align: center;
        }
        
        .page-header h1 {
            color: var(--primary);
            font-size: 2.8em;
            font-weight: 800;
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.1);
        }
        
        .page-header .subtitle {
            color: #666;
            font-size: 1.1em;
        }
        
        .page-header .stats-quick {
            display: flex;
            justify-content: center;
            gap: 30px;
            margin-top: 20px;
            flex-wrap: wrap;
        }
        
        .stat-quick {
            text-align: center;
        }
        
        .stat-quick .number {
            font-size: 2em;
            font-weight: bold;
            color: var(--primary);
        }
        
        .stat-quick .label {
            color: #888;
            font-size: 0.9em;
        }
        
        .card {
            border: none;
            border-radius: 15px;
            box-shadow: 0 5px 20px rgba(0,0,0,0.15);
            margin-bottom: 25px;
            animation: fadeInUp 0.5s ease-in-out;
            transition: transform 0.3s ease, box-shadow 0.3s ease;
        }
        
        .card:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
        }
        
        @keyframes fadeInUp {
            from {
                opacity: 0;
                transform: translateY(30px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }
        
        .card-header {
            background: linear-gradient(135deg, var(--primary), var(--secondary));
            color: white;
            border-radius: 15px 15px 0 0 !important;
            padding: 20px 25px;
            font-weight: 700;
            font-size: 1.3em;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .card-header .badge {
            font-size: 0.7em;
            padding: 5px 12px;
        }
        
        .card-body {
            padding: 25px;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .stat-card {
            background: white;
            border-radius: 15px;
            padding: 25px;
            box-shadow: 0 5px 20px rgba(0,0,0,0.1);
            transition: all 0.3s ease;
            position: relative;
            overflow: hidden;
        }
        
        .stat-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 5px;
            height: 100%;
            background: var(--primary);
        }
        
        .stat-card:hover {
            transform: translateY(-10px) scale(1.02);
            box-shadow: 0 15px 40px rgba(0,0,0,0.2);
        }
        
        .stat-card .icon {
            font-size: 3em;
            margin-bottom: 15px;
            opacity: 0.8;
        }
        
        .stat-card .number {
            font-size: 2.5em;
            font-weight: 800;
            background: linear-gradient(135deg, var(--primary), var(--secondary));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            margin: 10px 0;
        }
        
        .stat-card .label {
            color: #666;
            font-size: 1em;
            font-weight: 600;
        }
        
        .stat-card .progress {
            height: 8px;
            margin-top: 15px;
            border-radius: 10px;
        }
        
        .chart-container {
            position: relative;
            height: 400px;
            margin: 20px 0;
        }
        
        .chart-small {
            height: 300px;
        }
        
        .filter-section {
            background: white;
            border-radius: 15px;
            padding: 30px;
            margin-bottom: 30px;
            box-shadow: 0 5px 20px rgba(0,0,0,0.1);
        }
        
        .filter-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 25px;
            padding-bottom: 15px;
            border-bottom: 2px solid #f0f0f0;
        }
        
        .filter-header h3 {
            color: var(--primary);
            margin: 0;
            font-size: 1.5em;
        }
        
        .filter-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }
        
        .filter-item label {
            font-weight: 600;
            color: #555;
            margin-bottom: 8px;
            display: block;
        }
        
        .form-control, .form-select {
            border-radius: 10px;
            border: 2px solid #e0e0e0;
            padding: 12px 15px;
            transition: all 0.3s ease;
        }
        
        .form-control:focus, .form-select:focus {
            border-color: var(--primary);
            box-shadow: 0 0 0 0.25rem rgba(102, 126, 234, 0.1);
        }
        
        .btn-filter {
            background: linear-gradient(135deg, var(--primary), var(--secondary));
            color: white;
            border: none;
            padding: 12px 35px;
            border-radius: 25px;
            font-weight: 600;
            transition: all 0.3s ease;
            box-shadow: 0 5px 15px rgba(102, 126, 234, 0.3);
        }
        
        .btn-filter:hover {
            transform: translateY(-3px);
            box-shadow: 0 8px 25px rgba(102, 126, 234, 0.5);
            color: white;
        }
        
        .btn-reset {
            background: #6c757d;
            color: white;
            border: none;
            padding: 12px 35px;
            border-radius: 25px;
            font-weight: 600;
        }
        
        .btn-export {
            background: linear-gradient(135deg, var(--success), #059669);
            color: white;
            border: none;
            padding: 10px 25px;
            border-radius: 20px;
            font-weight: 600;
            margin-left: 10px;
        }
        
        .table-container {
            background: white;
            border-radius: 15px;
            overflow: hidden;
            box-shadow: 0 5px 20px rgba(0,0,0,0.1);
        }
        
        .table {
            margin: 0;
        }
        
        .table thead {
            background: linear-gradient(135deg, var(--primary), var(--secondary));
            color: white;
        }
        
        .table thead th {
            padding: 18px 15px;
            font-weight: 700;
            border: none;
            text-transform: uppercase;
            font-size: 0.85em;
            letter-spacing: 0.5px;
        }
        
        .table tbody tr {
            transition: all 0.3s ease;
            border-bottom: 1px solid #f0f0f0;
        }
        
        .table tbody tr:hover {
            background: linear-gradient(90deg, #f8f9fa 0%, #ffffff 100%);
            transform: scale(1.01);
            box-shadow: 0 5px 15px rgba(0,0,0,0.05);
        }
        
        .table tbody td {
            padding: 18px 15px;
            vertical-align: middle;
        }
        
        .log-entry {
            background: white;
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 15px;
            border-right: 5px solid;
            transition: all 0.3s ease;
            box-shadow: 0 2px 10px rgba(0,0,0,0.08);
        }
        
        .log-entry:hover {
            transform: translateX(-8px);
            box-shadow: 0 8px 25px rgba(0,0,0,0.15);
        }
        
        .log-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
            flex-wrap: wrap;
            gap: 10px;
        }
        
        .log-bot-info {
            display: flex;
            align-items: center;
            gap: 15px;
        }
        
        .bot-badge {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 8px 18px;
            border-radius: 25px;
            color: white;
            font-weight: 700;
            font-size: 0.95em;
            box-shadow: 0 3px 10px rgba(0,0,0,0.2);
        }
        
        .verified-badge {
            background: linear-gradient(135deg, var(--success), #059669);
            padding: 5px 15px;
            border-radius: 20px;
            color: white;
            font-size: 0.85em;
            font-weight: 700;
            box-shadow: 0 2px 8px rgba(16, 185, 129, 0.3);
        }
        
        .unverified-badge {
            background: linear-gradient(135deg, var(--warning), #D97706);
            padding: 5px 15px;
            border-radius: 20px;
            color: white;
            font-size: 0.85em;
            font-weight: 700;
            box-shadow: 0 2px 8px rgba(245, 158, 11, 0.3);
        }
        
        .log-meta {
            display: flex;
            gap: 20px;
            flex-wrap: wrap;
            align-items: center;
        }
        
        .status-badge {
            padding: 6px 15px;
            border-radius: 20px;
            font-weight: 700;
            font-size: 0.9em;
        }
        
        .status-200 { 
            background: #D1FAE5;
            color: #065F46;
        }
        
        .status-404 { 
            background: #FEE2E2;
            color: #991B1B;
        }
        
        .status-301, .status-302 { 
            background: #FEF3C7;
            color: #92400E;
        }
        
        .status-500 {
            background: #FEE2E2;
            color: #7F1D1D;
        }
        
        .log-details {
            background: #F9FAFB;
            padding: 15px;
            border-radius: 10px;
            margin-top: 15px;
        }
        
        .log-details-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 12px;
        }
        
        .detail-item {
            display: flex;
            align-items: flex-start;
            gap: 10px;
        }
        
        .detail-label {
            font-weight: 700;
            color: #6B7280;
            min-width: 80px;
            font-size: 0.9em;
        }
        
        .detail-value {
            flex: 1;
            color: #374151;
            font-family: 'Courier New', monospace;
            word-break: break-all;
            font-size: 0.9em;
        }
        
        .pagination-container {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-top: 30px;
            padding: 20px;
            background: white;
            border-radius: 15px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }
        
        .pagination {
            margin: 0;
        }
        
        .page-link {
            color: var(--primary);
            border: 2px solid #e0e0e0;
            border-radius: 8px;
            margin: 0 3px;
            padding: 10px 18px;
            font-weight: 600;
            transition: all 0.3s ease;
        }
        
        .page-link:hover {
            background: var(--primary);
            color: white;
            border-color: var(--primary);
            transform: translateY(-2px);
        }
        
        .page-item.active .page-link {
            background: linear-gradient(135deg, var(--primary), var(--secondary));
            border-color: var(--primary);
        }
        
        .search-box {
            position: relative;
            margin-bottom: 20px;
        }
        
        .search-box input {
            padding-right: 50px;
        }
        
        .search-box i {
            position: absolute;
            left: 20px;
            top: 50%;
            transform: translateY(-50%);
            color: #999;
            font-size: 1.2em;
        }
        
        .loading-overlay {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.8);
            display: none;
            justify-content: center;
            align-items: center;
            z-index: 9999;
        }
        
        .loading-spinner {
            width: 80px;
            height: 80px;
            border: 8px solid rgba(255,255,255,0.2);
            border-top-color: var(--primary);
            border-radius: 50%;
            animation: spin 1s linear infinite;
        }
        
        @keyframes spin {
            to { transform: rotate(360deg); }
        }
        
        @media (max-width: 768px) {
            .page-header h1 {
                font-size: 2em;
            }
            
            .stats-grid {
                grid-template-columns: 1fr;
            }
            
            .filter-grid {
                grid-template-columns: 1fr;
            }
            
            .chart-container {
                height: 300px;
            }
            
            .log-header {
                flex-direction: column;
                align-items: flex-start;
            }
            
            .table-container {
                overflow-x: auto;
            }
        }
        
        @media print {
            body {
                background: white;
            }
            
            .no-print {
                display: none !important;
            }
            
            .card {
                break-inside: avoid;
                page-break-inside: avoid;
            }
        }
    </style>
</head>
<body>
    <div class="main-container">
        <div class="page-header">
            <h1>
                <i class="bi bi-robot"></i>
                تحلیلگر کامل لاگ بات‌ها + کاربران
            </h1>
            <p class="subtitle">
                <i class="bi bi-shield-check"></i>
                با IP Range Verification، شناسایی کاربران عادی و قابلیت‌های پیشرفته
            </p>
            
            <?php if (isset($success)): ?>
            <div class="alert alert-success mt-3" role="alert">
                <i class="bi bi-check-circle-fill"></i>
                <?php echo htmlspecialchars($success); ?>
            </div>
            <?php endif; ?>
            
            <?php if (isset($error)): ?>
            <div class="alert alert-danger mt-3" role="alert">
                <i class="bi bi-exclamation-triangle-fill"></i>
                <?php echo htmlspecialchars($error); ?>
            </div>
            <?php endif; ?>
            
            <?php if ($analyzer && ($logs || $nonBotLogs)): ?>
            <div class="stats-quick">
                <div class="stat-quick">
                    <div class="number"><?php echo number_format(count($logs)); ?></div>
                    <div class="label">🤖 لاگ‌های بات</div>
                </div>
                <div class="stat-quick">
                    <div class="number"><?php echo number_format(count($nonBotLogs)); ?></div>
                    <div class="label">👤 لاگ‌های کاربر</div>
                </div>
                <div class="stat-quick">
                    <div class="number"><?php echo number_format(count($logs) + count($nonBotLogs)); ?></div>
                    <div class="label">📊 کل لاگ‌ها</div>
                </div>
                <div class="stat-quick">
                    <div class="number">
                        <?php 
                        $totalBandwidth = 0;
                        foreach ($stats as $bot) {
                            $totalBandwidth += $bot['bandwidth'];
                        }
                        $totalBandwidth += $nonBotStats['bandwidth'];
                        echo BotLogAnalyzer::formatBytes($totalBandwidth);
                        ?>
                    </div>
                    <div class="label">💾 کل ترافیک</div>
                </div>
            </div>
            <?php endif; ?>
        </div>

        <?php if ($analyzer && $analyzer->getIPRangeManager()): ?>
        <div class="card no-print">
            <div class="card-header">
                <span>
                    <i class="bi bi-diagram-3"></i>
                    وضعیت IP Range Files
                </span>
                <span class="badge bg-light text-dark">
                    <?php echo number_format($analyzer->getIPRangeManager()->getTotalRanges()); ?> رنج
                </span>
            </div>
            <div class="card-body">
                <div class="row">
                    <div class="col-md-6">
                        <p class="mb-2">
                            <strong>مسیر فایل لاگ:</strong><br>
                            <code><?php echo htmlspecialchars($analyzer->getLogFile() ?: 'یافت نشد'); ?></code>
                        </p>
                    </div>
                    <div class="col-md-6">
                        <p class="mb-2">
                            <strong>فایل‌های JSON:</strong><br>
                            <?php 
                            $loadedFiles = $analyzer->getIPRangeManager()->getLoadedFiles();
                            if (!empty($loadedFiles)): 
                            ?>
                                <span class="badge bg-success"><?php echo count($loadedFiles); ?> فایل</span>
                                <small class="text-muted d-block mt-1">
                                    <?php echo implode(', ', array_slice($loadedFiles, 0, 3)); ?>
                                    <?php if (count($loadedFiles) > 3): ?>
                                        و <?php echo count($loadedFiles) - 3; ?> مورد دیگر...
                                    <?php endif; ?>
                                </small>
                            <?php else: ?>
                                <span class="badge bg-warning">⚠️ هیچ فایلی بارگذاری نشد</span>
                            <?php endif; ?>
                        </p>
                    </div>
                </div>
            </div>
        </div>
        <?php endif; ?>

        <div class="filter-section no-print">
            <div class="filter-header">
                <h3>
                    <i class="bi bi-funnel"></i>
                    فیلترهای پیشرفته
                </h3>
                <div>
                    <button type="button" class="btn btn-export" onclick="exportToExcel()">
                        <i class="bi bi-file-earmark-excel"></i>
                        خروجی Excel
                    </button>
                </div>
            </div>
            
            <form method="GET" id="filterForm">
                <div class="filter-grid">
                    <div class="filter-item">
                        <label>
                            <i class="bi bi-calendar3"></i>
                            بازه زمانی
                        </label>
                        <select name="days" class="form-select">
                            <option value="1" <?php echo $daysBack == 1 ? 'selected' : ''; ?>>امروز (1 روز)</option>
                            <option value="2" <?php echo $daysBack == 2 ? 'selected' : ''; ?>>2 روز اخیر</option>
                            <option value="3" <?php echo $daysBack == 3 ? 'selected' : ''; ?>>3 روز اخیر</option>
                            <option value="4" <?php echo $daysBack == 4 ? 'selected' : ''; ?>>4 روز اخیر</option>
                            <option value="5" <?php echo $daysBack == 5 ? 'selected' : ''; ?>>5 روز اخیر</option>
                            <option value="7" <?php echo $daysBack == 7 ? 'selected' : ''; ?>>هفته اخیر (7 روز)</option>
                            <option value="14" <?php echo $daysBack == 14 ? 'selected' : ''; ?>>2 هفته اخیر</option>
                            <option value="30" <?php echo $daysBack == 30 ? 'selected' : ''; ?>>ماه اخیر (30 روز)</option>
                            <option value="60" <?php echo $daysBack == 60 ? 'selected' : ''; ?>>2 ماه اخیر</option>
                            <option value="90" <?php echo $daysBack == 90 ? 'selected' : ''; ?>>3 ماه اخیر</option>
                        </select>
                    </div>
                    
                    <div class="filter-item">
                        <label>
                            <i class="bi bi-diagram-3"></i>
                            نوع لاگ
                        </label>
                        <select name="log_type" class="form-select" id="logTypeFilter">
                            <option value="all" <?php echo $logTypeFilter === 'all' ? 'selected' : ''; ?>>
                                📊 همه (بات + کاربر)
                            </option>
                            <option value="bot" <?php echo $logTypeFilter === 'bot' ? 'selected' : ''; ?>>
                                🤖 فقط بات‌ها
                            </option>
                            <option value="nonbot" <?php echo $logTypeFilter === 'nonbot' ? 'selected' : ''; ?>>
                                👤 فقط کاربران عادی
                            </option>
                        </select>
                    </div>
                    
                    <div class="filter-item">
                        <label>
                            <i class="bi bi-hash"></i>
                            تعداد رکورد
                        </label>
                        <select name="limit" class="form-select">
                            <option value="1000" <?php echo $limit == 1000 ? 'selected' : ''; ?>>1,000</option>
                            <option value="5000" <?php echo $limit == 5000 ? 'selected' : ''; ?>>5,000</option>
                            <option value="10000" <?php echo $limit == 10000 ? 'selected' : ''; ?>>10,000</option>
                            <option value="25000" <?php echo $limit == 25000 ? 'selected' : ''; ?>>25,000</option>
                            <option value="50000" <?php echo $limit == 50000 ? 'selected' : ''; ?>>50,000</option>
                        </select>
                    </div>
                    
                    <div class="filter-item">
                        <label>
                            <i class="bi bi-robot"></i>
                            نوع بات
                        </label>
                        <select name="bot" class="form-select" id="botFilter">
                            <option value="all">همه بات‌ها</option>
                            <?php if (isset($stats)): foreach ($stats as $bot): ?>
                            <option value="<?php echo htmlspecialchars($bot['name']); ?>" 
                                    <?php echo $botFilter === $bot['name'] ? 'selected' : ''; ?>>
                                <?php echo $bot['icon'] . ' ' . htmlspecialchars($bot['name']); ?> 
                                (<?php echo number_format($bot['count']); ?>)
                            </option>
                            <?php endforeach; endif; ?>
                        </select>
                    </div>
                    
                    <div class="filter-item">
                        <label>
                            <i class="bi bi-check-circle"></i>
                            وضعیت تأیید
                        </label>
                        <select name="verification" class="form-select">
                            <option value="all" <?php echo $verificationFilter === 'all' ? 'selected' : ''; ?>>همه</option>
                            <option value="verified" <?php echo $verificationFilter === 'verified' ? 'selected' : ''; ?>>تأیید شده</option>
                            <option value="unverified" <?php echo $verificationFilter === 'unverified' ? 'selected' : ''; ?>>تأیید نشده</option>
                        </select>
                    </div>
                    
                    <div class="filter-item">
                        <label>
                            <i class="bi bi-activity"></i>
                            کد وضعیت
                        </label>
                        <select name="status" class="form-select">
                            <option value="all" <?php echo $statusFilter === 'all' ? 'selected' : ''; ?>>همه</option>
                            <option value="200" <?php echo $statusFilter === '200' ? 'selected' : ''; ?>>200 (موفق)</option>
                            <option value="404" <?php echo $statusFilter === '404' ? 'selected' : ''; ?>>404 (یافت نشد)</option>
                            <option value="4xx" <?php echo $statusFilter === '4xx' ? 'selected' : ''; ?>>4xx (خطای کلاینت)</option>
                            <option value="5xx" <?php echo $statusFilter === '5xx' ? 'selected' : ''; ?>>5xx (خطای سرور)</option>
                        </select>
                    </div>
                    
                    <div class="filter-item">
                        <label>
                            <i class="bi bi-calendar-date"></i>
                            تاریخ خاص
                        </label>
                        <input type="date" name="date_filter" class="form-control" 
                               value="<?php echo htmlspecialchars($dateFilter); ?>">
                    </div>
                    
                    <div class="filter-item">
                        <label>
                            <i class="bi bi-globe"></i>
                            فیلتر IP
                        </label>
                        <input type="text" name="ip_filter" class="form-control" 
                               placeholder="مثال: 192.168"
                               value="<?php echo htmlspecialchars($ipFilter); ?>">
                    </div>
                    
                    <div class="filter-item">
                        <label>
                            <i class="bi bi-link-45deg"></i>
                            فیلتر URL
                        </label>
                        <input type="text" name="url_filter" class="form-control" 
                               placeholder="مثال: /wp-admin"
                               value="<?php echo htmlspecialchars($urlFilter); ?>">
                    </div>
                </div>
                
                <div class="d-flex justify-content-between align-items-center mt-4">
                    <div>
                        <button type="submit" class="btn btn-filter">
                            <i class="bi bi-search"></i>
                            اعمال فیلترها
                        </button>
                        <button type="button" class="btn btn-reset" onclick="resetFilters()">
                            <i class="bi bi-arrow-counterclockwise"></i>
                            پاکسازی
                        </button>
                    </div>
                    
                    <div class="form-check">
                        <input class="form-check-input" type="checkbox" name="auto_cleanup" 
                               id="autoCleanup" <?php echo $autoCleanup ? 'checked' : ''; ?>>
                        <label class="form-check-label" for="autoCleanup">
                            <i class="bi bi-trash"></i>
                            پاکسازی خودکار
                        </label>
                    </div>
                </div>
            </form>
            
            <div class="search-box mt-4">
                <input type="text" class="form-control" id="liveSearch" 
                       placeholder="🔍 جستجوی زنده در نتایج...">
                <i class="bi bi-search"></i>
            </div>
        </div>

        <?php if (isset($logs) && isset($stats) && (count($logs) > 0 || count($nonBotLogs) > 0)): ?>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="icon">🤖</div>
                <div class="number"><?php echo number_format(count($logs)); ?></div>
                <div class="label">لاگ‌های بات</div>
                <div class="progress">
                    <div class="progress-bar bg-primary" style="width: <?php echo (count($logs) / (count($logs) + count($nonBotLogs)) * 100); ?>%"></div>
                </div>
            </div>
            
            <div class="stat-card">
                <div class="icon">👤</div>
                <div class="number"><?php echo number_format(count($nonBotLogs)); ?></div>
                <div class="label">لاگ‌های کاربران</div>
                <div class="progress">
                    <div class="progress-bar bg-success" style="width: <?php echo (count($nonBotLogs) / (count($logs) + count($nonBotLogs)) * 100); ?>%"></div>
                </div>
            </div>
            
            <div class="stat-card">
                <div class="icon">✅</div>
                <?php 
                $verifiedCount = 0;
                foreach ($logs as $log) {
                    if ($log['ip_verified']) $verifiedCount++;
                }
                $verificationRate = count($logs) > 0 ? ($verifiedCount / count($logs) * 100) : 0;
                ?>
                <div class="number"><?php echo number_format($verifiedCount); ?></div>
                <div class="label">بات تأیید شده IP</div>
                <div class="progress">
                    <div class="progress-bar bg-success" style="width: <?php echo $verificationRate; ?>%"></div>
                </div>
                <small class="text-muted"><?php echo number_format($verificationRate, 1); ?>% نرخ تأیید</small>
            </div>
            
            <div class="stat-card">
                <div class="icon">💾</div>
                <?php 
                $totalBandwidth = 0;
                foreach ($stats as $bot) {
                    $totalBandwidth += $bot['bandwidth'];
                }
                $totalBandwidth += $nonBotStats['bandwidth'];
                ?>
                <div class="number" style="font-size: 2em;"><?php echo BotLogAnalyzer::formatBytes($totalBandwidth); ?></div>
                <div class="label">کل ترافیک</div>
            </div>
        </div>

        <div class="row mb-4">
            <div class="col-lg-6 mb-4">
                <div class="card">
                    <div class="card-header">
                        <span>
                            <i class="bi bi-pie-chart"></i>
                            📊 توزیع بازدید بات‌ها
                        </span>
                        <span class="badge bg-light text-dark"><?php echo count($stats); ?> بات</span>
                    </div>
                    <div class="card-body">
                        <div class="chart-container">
                            <canvas id="botPieChart"></canvas>
                        </div>
                    </div>
                </div>
            </div>
            
            <div class="col-lg-6 mb-4">
                <div class="card">
                    <div class="card-header">
                        <span>
                            <i class="bi bi-bar-chart"></i>
                            📈 نمودار میله‌ای بازدیدها
                        </span>
                    </div>
                    <div class="card-body">
                        <div class="chart-container">
                            <canvas id="botBarChart"></canvas>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <div class="card mb-4">
            <div class="card-header">
                <span>
                    <i class="bi bi-graph-up"></i>
                    📉 نمودار فعالیت ساعتی
                </span>
                <span class="badge bg-light text-dark">
                    <?php 
                    if ($daysBack == 1) {
                        echo 'امروز: ' . date('Y-m-d');
                    } else {
                        echo 'آخرین ' . $daysBack . ' روز';
                    }
                    ?>
                </span>
            </div>
            <div class="card-body">
                <div class="chart-container">
                    <canvas id="hourlyLineChart"></canvas>
                </div>
                <?php if ($logTypeFilter !== 'all'): ?>
                <div class="alert alert-info mt-3 mb-0">
                    <i class="bi bi-funnel"></i>
                    <strong>فیلتر فعال:</strong> 
                    <?php 
                    if ($logTypeFilter === 'bot') {
                        echo '🤖 فقط بات‌ها';
                    } else {
                        echo '👤 فقط کاربران عادی';
                    }
                    ?>
                </div>
                <?php endif; ?>
            </div>
        </div>

        <div class="card mb-4">
            <div class="card-header">
                <span>
                    <i class="bi bi-calendar3"></i>
                    📅 نمودار روزانه فعالیت
                </span>
                <span class="badge bg-light text-dark">
                    آخرین <?php echo min($daysBack, 30); ?> روز
                </span>
            </div>
            <div class="card-body">
                <div class="chart-container">
                    <canvas id="dailyTimelineChart"></canvas>
                </div>
                <?php if ($logTypeFilter !== 'all'): ?>
                <div class="alert alert-info mt-3 mb-0">
                    <i class="bi bi-funnel"></i>
                    <strong>فیلتر فعال:</strong> 
                    <?php 
                    if ($logTypeFilter === 'bot') {
                        echo '🤖 نمایش فقط بازدیدهای بات‌ها';
                    } elseif ($logTypeFilter === 'nonbot') {
                        echo '👤 نمایش فقط بازدیدهای کاربران عادی';
                    }
                    ?>
                </div>
                <?php endif; ?>
            </div>
        </div>

        <?php if (count($stats) > 0): ?>
        <div class="card mb-4">
            <div class="card-header">
                <span>
                    <i class="bi bi-table"></i>
                    📋 آمار تفصیلی بات‌ها
                </span>
                <button type="button" class="btn btn-sm btn-export" onclick="exportTableToExcel('botStatsTable', 'bot_statistics.xlsx')">
                    <i class="bi bi-download"></i>
                    دانلود Excel
                </button>
            </div>
            <div class="card-body p-0">
                <div class="table-container">
                    <table class="table table-hover mb-0" id="botStatsTable">
                        <thead>
                            <tr>
                                <th>نام بات</th>
                                <th>کل بازدید</th>
                                <th>IP تأیید شده</th>
                                <th>درصد تأیید</th>
                                <th>IP های یکتا</th>
                                <th>URL های یکتا</th>
                                <th>حجم ترافیک</th>
                                <th>اولین بازدید</th>
                                <th>آخرین بازدید</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($stats as $bot): ?>
                            <tr>
                                <td>
                                    <span class="bot-badge" style="background-color: <?php echo $bot['color']; ?>">
                                        <?php echo $bot['icon'] . ' ' . htmlspecialchars($bot['name']); ?>
                                    </span>
                                </td>
                                <td><strong style="font-size: 1.1em;"><?php echo number_format($bot['count']); ?></strong></td>
                                <td><strong class="text-success" style="font-size: 1.1em;"><?php echo number_format($bot['verified_count']); ?></strong></td>
                                <td>
                                    <?php 
                                    $verificationRate = $bot['count'] > 0 ? ($bot['verified_count'] / $bot['count'] * 100) : 0;
                                    $rateColor = $verificationRate >= 80 ? 'success' : ($verificationRate >= 50 ? 'warning' : 'danger');
                                    ?>
                                    <div class="progress" style="height: 30px;">
                                        <div class="progress-bar bg-<?php echo $rateColor; ?>" 
                                             style="width: <?php echo $verificationRate; ?>%">
                                            <strong><?php echo number_format($verificationRate, 1); ?>%</strong>
                                        </div>
                                    </div>
                                </td>
                                <td><?php echo count($bot['ips']); ?></td>
                                <td><?php echo count($bot['urls']); ?></td>
                                <td><span class="badge bg-info"><?php echo BotLogAnalyzer::formatBytes($bot['bandwidth']); ?></span></td>
                                <td><small><?php echo date('Y-m-d H:i', $bot['first_seen']); ?></small></td>
                                <td><small><?php echo date('Y-m-d H:i', $bot['last_seen']); ?></small></td>
                            </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
        <?php endif; ?>

        <?php if (isset($nonBotStats) && $nonBotStats['total'] > 0): ?>
        <div class="card mb-4" style="border-top: 5px solid #34A853;">
            <div class="card-header" style="background: linear-gradient(135deg, #34A853, #0F9D58);">
                <span>
                    <i class="bi bi-people"></i>
                    👥 آمار ترافیک کاربران عادی
                </span>
                <span class="badge bg-light text-dark">
                    <?php echo number_format($nonBotStats['total']); ?> بازدید
                </span>
            </div>
            <div class="card-body">
                <div class="row">
                    <div class="col-md-3 mb-3">
                        <div class="stat-card" style="border-right-color: #34A853;">
                            <div class="icon">👥</div>
                            <div class="number"><?php echo number_format($nonBotStats['total']); ?></div>
                            <div class="label">کل بازدیدها</div>
                        </div>
                    </div>
                    <div class="col-md-3 mb-3">
                        <div class="stat-card" style="border-right-color: #4285F4;">
                            <div class="icon">🌐</div>
                            <div class="number"><?php echo number_format($nonBotStats['unique_ips']); ?></div>
                            <div class="label">IP های یکتا</div>
                        </div>
                    </div>
                    <div class="col-md-3 mb-3">
                        <div class="stat-card" style="border-right-color: #FBBC04;">
                            <div class="icon">📄</div>
                            <div class="number"><?php echo number_format($nonBotStats['unique_urls']); ?></div>
                            <div class="label">صفحات بازدید شده</div>
                        </div>
                    </div>
                    <div class="col-md-3 mb-3">
                        <div class="stat-card" style="border-right-color: #EA4335;">
                            <div class="icon">💾</div>
                            <div class="number" style="font-size: 1.8em;">
                                <?php echo BotLogAnalyzer::formatBytes($nonBotStats['bandwidth']); ?>
                            </div>
                            <div class="label">حجم ترافیک</div>
                        </div>
                    </div>
                </div>
                
                <?php if (!empty($nonBotStats['user_types'])): ?>
                <div class="row mt-4">
                    <div class="col-12">
                        <h5 class="mb-3">
                            <i class="bi bi-browser-chrome"></i>
                            توزیع نوع کاربران
                        </h5>
                        <div class="row">
                            <?php foreach ($nonBotStats['user_types'] as $type => $data): ?>
                            <div class="col-md-3 col-sm-6 mb-3">
                                <div class="card" style="border-right: 4px solid <?php echo $data['color']; ?>;">
                                    <div class="card-body text-center">
                                        <div style="font-size: 2.5em;"><?php echo $data['icon']; ?></div>
                                        <h4 class="mt-2"><?php echo number_format($data['count']); ?></h4>
                                        <small class="text-muted"><?php echo htmlspecialchars($type); ?></small>
                                        <div class="progress mt-2" style="height: 6px;">
                                            <div class="progress-bar" 
                                                 style="width: <?php echo ($data['count'] / $nonBotStats['total'] * 100); ?>%; background-color: <?php echo $data['color']; ?>;">
                                            </div>
                                        </div>
                                        <small class="text-muted">
                                            <?php echo number_format($data['count'] / $nonBotStats['total'] * 100, 1); ?>%
                                        </small>
                                    </div>
                                </div>
                            </div>
                            <?php endforeach; ?>
                        </div>
                    </div>
                </div>
                <?php endif; ?>
            </div>
        </div>
        <?php endif; ?>
        
        <?php 
        $displayBotLogs = ($logTypeFilter === 'all' || $logTypeFilter === 'bot');
        $displayNonBotLogs = ($logTypeFilter === 'all' || $logTypeFilter === 'nonbot');
        ?>
        
        <?php if ($displayBotLogs && count($logs) > 0): ?>
        <div class="card">
            <div class="card-header">
                <span>
                    <i class="bi bi-clock-history"></i>
                    ⏰ لاگ‌های اخیر بات‌ها
                </span>
                <span class="badge bg-light text-dark">
                    <?php echo number_format(count($logs)); ?> مورد
                </span>
            </div>
            <div class="card-body">
                <div class="row mb-4">
                    <div class="col-md-3">
                        <div class="alert alert-info mb-0">
                            <strong>کل:</strong> <?php echo number_format(count($logs)); ?>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="alert alert-success mb-0">
                            <strong>تأیید شده:</strong> <?php echo number_format($verifiedCount); ?>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="alert alert-warning mb-0">
                            <strong>بدون تأیید:</strong> <?php echo number_format(count($logs) - $verifiedCount); ?>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="alert alert-primary mb-0">
                            <strong>فیلتر شده:</strong> <span id="filteredCount"><?php echo number_format(count($logs)); ?></span>
                        </div>
                    </div>
                </div>

                <div id="logsContainer">
                    <?php 
                    $displayLogs = $paginatedLogs;
                    foreach ($displayLogs as $log): 
                    ?>
                    <div class="log-entry" 
                         style="border-right-color: <?php echo $log['bot_color']; ?>"
                         data-bot="<?php echo htmlspecialchars($log['bot_name']); ?>"
                         data-status="<?php echo $log['status_code']; ?>"
                         data-verification="<?php echo $log['ip_verified'] ? 'verified' : 'unverified'; ?>"
                         data-date="<?php echo $log['date']; ?>"
                         data-ip="<?php echo htmlspecialchars($log['ip']); ?>"
                         data-url="<?php echo htmlspecialchars($log['url']); ?>">
                        
                        <div class="log-header">
                            <div class="log-bot-info">
                                <span class="bot-badge" style="background-color: <?php echo $log['bot_color']; ?>">
                                    <?php echo $log['bot_icon'] . ' ' . htmlspecialchars($log['bot_name']); ?>
                                </span>
                                
                                <?php if ($log['ip_verified']): ?>
                                <span class="verified-badge">
                                    <i class="bi bi-shield-check"></i>
                                    IP تأیید شده
                                </span>
                                <?php else: ?>
                                <span class="unverified-badge">
                                    <i class="bi bi-exclamation-triangle"></i>
                                    فقط UA
                                </span>
                                <?php endif; ?>
                                
                                <span class="badge bg-secondary">
                                    <i class="bi bi-calendar3"></i>
                                    <?php echo $log['datetime']; ?>
                                </span>
                            </div>
                            
                            <div class="log-meta">
                                <span class="badge bg-dark"><?php echo $log['method']; ?></span>
                                <span class="status-badge status-<?php echo $log['status_code']; ?>">
                                    <?php echo $log['status_code']; ?>
                                </span>
                            </div>
                        </div>
                        
                        <div class="log-details">
                            <div class="log-details-grid">
                                <div class="detail-item">
                                    <span class="detail-label">
                                        <i class="bi bi-geo-alt"></i>
                                        IP:
                                    </span>
                                    <span class="detail-value">
                                        <?php echo htmlspecialchars($log['ip']); ?>
                                    </span>
                                </div>
                                
                                <div class="detail-item">
                                    <span class="detail-label">
                                        <i class="bi bi-link-45deg"></i>
                                        URL:
                                    </span>
                                    <span class="detail-value">
                                        <?php echo htmlspecialchars($log['url']); ?>
                                    </span>
                                </div>
                                
                                <div class="detail-item">
                                    <span class="detail-label">
                                        <i class="bi bi-check-circle"></i>
                                        تأیید:
                                    </span>
                                    <span class="detail-value">
                                        <?php echo htmlspecialchars($log['verification']); ?>
                                    </span>
                                </div>
                                
                                <div class="detail-item">
                                    <span class="detail-label">
                                        <i class="bi bi-hdd"></i>
                                        حجم:
                                    </span>
                                    <span class="detail-value">
                                        <?php echo BotLogAnalyzer::formatBytes($log['bytes']); ?>
                                    </span>
                                </div>
                                
                                <?php if ($log['referrer'] && $log['referrer'] !== '-'): ?>
                                <div class="detail-item" style="grid-column: 1 / -1;">
                                    <span class="detail-label">
                                        <i class="bi bi-arrow-left-circle"></i>
                                        Referrer:
                                    </span>
                                    <span class="detail-value">
                                        <?php echo htmlspecialchars(substr($log['referrer'], 0, 100)); ?>
                                    </span>
                                </div>
                                <?php endif; ?>
                                
                                <div class="detail-item" style="grid-column: 1 / -1;">
                                    <span class="detail-label">
                                        <i class="bi bi-browser-chrome"></i>
                                        User-Agent:
                                    </span>
                                    <span class="detail-value">
                                        <?php echo htmlspecialchars(substr($log['user_agent'], 0, 150)); ?>
                                    </span>
                                </div>
                            </div>
                        </div>
                    </div>
                    <?php endforeach; ?>
                </div>
            </div>
        </div>

        <?php if ($totalLogs > $perPage): ?>
        <div class="pagination-container">
            <div>
                <strong>نمایش:</strong>
                <select class="form-select d-inline-block w-auto" onchange="changePageSize(this.value)">
                    <option value="50" <?php echo $perPage == 50 ? 'selected' : ''; ?>>50</option>
                    <option value="100" <?php echo $perPage == 100 ? 'selected' : ''; ?>>100</option>
                    <option value="200" <?php echo $perPage == 200 ? 'selected' : ''; ?>>200</option>
                    <option value="500" <?php echo $perPage == 500 ? 'selected' : ''; ?>>500</option>
                </select>
                از <?php echo number_format($totalLogs); ?> رکورد
                <span class="text-muted ms-2">
                    (صفحه <?php echo $currentPage; ?> از <?php echo $totalPages; ?>)
                </span>
            </div>
            
            <nav>
                <ul class="pagination mb-0">
                    <li class="page-item <?php echo $currentPage <= 1 ? 'disabled' : ''; ?>">
                        <a class="page-link" href="<?php echo $currentPage > 1 ? '?page=' . ($currentPage - 1) . '&per_page=' . $perPage . '&' . http_build_query(array_filter(['days' => $daysBack, 'limit' => $limit, 'bot' => $botFilter, 'status' => $statusFilter, 'verification' => $verificationFilter, 'log_type' => $logTypeFilter])) : '#'; ?>">
                            <i class="bi bi-chevron-right"></i>
                        </a>
                    </li>
                    
                    <?php
                    $range = 2;
                    $start = max(1, $currentPage - $range);
                    $end = min($totalPages, $currentPage + $range);
                    
                    if ($start > 1): ?>
                        <li class="page-item">
                            <a class="page-link" href="?page=1&per_page=<?php echo $perPage; ?>&<?php echo http_build_query(array_filter(['days' => $daysBack, 'limit' => $limit, 'bot' => $botFilter, 'status' => $statusFilter, 'verification' => $verificationFilter, 'log_type' => $logTypeFilter])); ?>">1</a>
                        </li>
                        <?php if ($start > 2): ?>
                            <li class="page-item disabled"><span class="page-link">...</span></li>
                        <?php endif;
                    endif;
                    
                    for ($i = $start; $i <= $end; $i++): ?>
                        <li class="page-item <?php echo $i == $currentPage ? 'active' : ''; ?>">
                            <a class="page-link" href="?page=<?php echo $i; ?>&per_page=<?php echo $perPage; ?>&<?php echo http_build_query(array_filter(['days' => $daysBack, 'limit' => $limit, 'bot' => $botFilter, 'status' => $statusFilter, 'verification' => $verificationFilter, 'log_type' => $logTypeFilter])); ?>">
                                <?php echo $i; ?>
                            </a>
                        </li>
                    <?php endfor;
                    
                    if ($end < $totalPages): ?>
                        <?php if ($end < $totalPages - 1): ?>
                            <li class="page-item disabled"><span class="page-link">...</span></li>
                        <?php endif; ?>
                        <li class="page-item">
                            <a class="page-link" href="?page=<?php echo $totalPages; ?>&per_page=<?php echo $perPage; ?>&<?php echo http_build_query(array_filter(['days' => $daysBack, 'limit' => $limit, 'bot' => $botFilter, 'status' => $statusFilter, 'verification' => $verificationFilter, 'log_type' => $logTypeFilter])); ?>">
                                <?php echo $totalPages; ?>
                            </a>
                        </li>
                    <?php endif; ?>
                    
                    <li class="page-item <?php echo $currentPage >= $totalPages ? 'disabled' : ''; ?>">
                        <a class="page-link" href="<?php echo $currentPage < $totalPages ? '?page=' . ($currentPage + 1) . '&per_page=' . $perPage . '&' . http_build_query(array_filter(['days' => $daysBack, 'limit' => $limit, 'bot' => $botFilter, 'status' => $statusFilter, 'verification' => $verificationFilter, 'log_type' => $logTypeFilter])) : '#'; ?>">
                            <i class="bi bi-chevron-left"></i>
                        </a>
                    </li>
                </ul>
            </nav>
        </div>
        <?php endif; ?>
        <?php endif; ?>

        <?php if ($displayNonBotLogs && count($nonBotLogs) > 0): ?>
        <div class="card mt-4">
            <div class="card-header" style="background: linear-gradient(135deg, #34A853, #0F9D58);">
                <span>
                    <i class="bi bi-people"></i>
                    👤 لاگ‌های ترافیک کاربران عادی
                </span>
                <span class="badge bg-light text-dark">
                    <?php echo number_format(count($nonBotLogs)); ?> مورد
                </span>
            </div>
            <div class="card-body">
                <div class="alert alert-info">
                    <i class="bi bi-info-circle"></i>
                    <strong>توضیح:</strong> این بخش شامل بازدیدهای کاربران واقعی، مرورگرها و ترافیک عادی است که بات شناخته شده نیستند.
                </div>
                
                <div id="nonBotLogsContainer">
                    <?php 
                    $displayNonBot = array_slice($nonBotLogs, 0, 50);
                    foreach ($displayNonBot as $log): 
                    ?>
                    <div class="log-entry" style="border-right-color: <?php echo $log['user_type']['color']; ?>">
                        <div class="log-header">
                            <div class="log-bot-info">
                                <span class="bot-badge" style="background-color: <?php echo $log['user_type']['color']; ?>">
                                    <?php echo $log['user_type']['icon'] . ' ' . htmlspecialchars($log['user_type']['type']); ?>
                                </span>
                                
                                <span class="badge bg-secondary">
                                    <i class="bi bi-calendar3"></i>
                                    <?php echo $log['datetime']; ?>
                                </span>
                            </div>
                            
                            <div class="log-meta">
                                <span class="badge bg-dark"><?php echo $log['method']; ?></span>
                                <span class="status-badge status-<?php echo $log['status_code']; ?>">
                                    <?php echo $log['status_code']; ?>
                                </span>
                            </div>
                        </div>
                        
                        <div class="log-details">
                            <div class="log-details-grid">
                                <div class="detail-item">
                                    <span class="detail-label">
                                        <i class="bi bi-geo-alt"></i>
                                        IP:
                                    </span>
                                    <span class="detail-value">
                                        <?php echo htmlspecialchars($log['ip']); ?>
                                    </span>
                                </div>
                                
                                <div class="detail-item">
                                    <span class="detail-label">
                                        <i class="bi bi-link-45deg"></i>
                                        URL:
                                    </span>
                                    <span class="detail-value">
                                        <?php echo htmlspecialchars($log['url']); ?>
                                    </span>
                                </div>
                                
                                <div class="detail-item">
                                    <span class="detail-label">
                                        <i class="bi bi-hdd"></i>
                                        حجم:
                                    </span>
                                    <span class="detail-value">
                                        <?php echo BotLogAnalyzer::formatBytes($log['bytes']); ?>
                                    </span>
                                </div>
                                
                                <?php if ($log['referrer'] && $log['referrer'] !== '-'): ?>
                                <div class="detail-item" style="grid-column: 1 / -1;">
                                    <span class="detail-label">
                                        <i class="bi bi-arrow-left-circle"></i>
                                        Referrer:
                                    </span>
                                    <span class="detail-value">
                                        <?php echo htmlspecialchars(substr($log['referrer'], 0, 100)); ?>
                                    </span>
                                </div>
                                <?php endif; ?>
                                
                                <div class="detail-item" style="grid-column: 1 / -1;">
                                    <span class="detail-label">
                                        <i class="bi bi-browser-chrome"></i>
                                        User-Agent:
                                    </span>
                                    <span class="detail-value">
                                        <?php echo htmlspecialchars(substr($log['user_agent'], 0, 150)); ?>
                                    </span>
                                </div>
                            </div>
                        </div>
                    </div>
                    <?php endforeach; ?>
                </div>
                
                <?php if (count($nonBotLogs) > 50): ?>
                <div class="alert alert-info mt-4 text-center">
                    <i class="bi bi-info-circle"></i>
                    نمایش 50 مورد اول از <?php echo number_format(count($nonBotLogs)); ?> لاگ کاربران عادی.
                </div>
                <?php endif; ?>
            </div>
        </div>
        <?php endif; ?>
        
        <?php elseif (isset($logs)): ?>
        <div class="card">
            <div class="card-body text-center py-5">
                <i class="bi bi-exclamation-triangle" style="font-size: 4em; color: #FFC107;"></i>
                <h3 class="mt-3">⚠️ هیچ لاگی در بازه زمانی انتخابی یافت نشد</h3>
                <a href="?" class="btn btn-primary mt-3">
                    <i class="bi bi-arrow-counterclockwise"></i>
                    ریست کردن فیلترها
                </a>
            </div>
        </div>
        <?php endif; ?>

    </div>
    
    <div class="loading-overlay" id="loadingOverlay">
        <div class="text-center">
            <div class="loading-spinner"></div>
            <p class="text-white mt-3">در حال پردازش...</p>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>

    <script>
    <?php if (isset($stats) && !empty($stats) && (count($logs) > 0 || count($nonBotLogs) > 0)): ?>
    const botStats = <?php echo json_encode(array_values($stats)); ?>;
    const chartColors = botStats.map(bot => bot.color);

    // 1. نمودار دایره‌ای
    const pieCtx = document.getElementById('botPieChart').getContext('2d');
    new Chart(pieCtx, {
        type: 'pie',
        data: {
            labels: botStats.map(bot => bot.icon + ' ' + bot.name),
            datasets: [{
                data: botStats.map(bot => bot.count),
                backgroundColor: chartColors,
                borderWidth: 3,
                borderColor: '#fff',
                hoverOffset: 10
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'right',
                    labels: {
                        font: { size: 13, weight: 'bold' },
                        padding: 15
                    }
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            const total = context.dataset.data.reduce((a, b) => a + b, 0);
                            const percentage = ((context.parsed / total) * 100).toFixed(1);
                            return context.label + ': ' + context.parsed.toLocaleString() + ' (' + percentage + '%)';
                        }
                    }
                }
            }
        }
    });

    // 2. نمودار میله‌ای
    const barCtx = document.getElementById('botBarChart').getContext('2d');
    new Chart(barCtx, {
        type: 'bar',
        data: {
            labels: botStats.map(bot => bot.icon + ' ' + bot.name),
            datasets: [{
                label: 'تعداد بازدید',
                data: botStats.map(bot => bot.count),
                backgroundColor: chartColors,
                borderRadius: 10
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: {
                        callback: function(value) { return value.toLocaleString(); }
                    }
                }
            }
        }
    });

    // 3. نمودار ساعتی - با فیلتر log_type
    <?php
    $hourlyData = array_fill(0, 24, 0);
    $todayDate = date('Y-m-d');
    
    $dataForChart = [];
    if ($logTypeFilter === 'bot') {
        $dataForChart = $logs;
    } elseif ($logTypeFilter === 'nonbot') {
        $dataForChart = $nonBotLogs;
    } else {
        $dataForChart = array_merge($logs, $nonBotLogs);
    }
    
    foreach ($dataForChart as $log) {
        if ($daysBack == 1) {
            if ($log['date'] === $todayDate) {
                $hourlyData[(int)$log['hour']]++;
            }
        } else {
            $hourlyData[(int)$log['hour']]++;
        }
    }
    ?>
    const hourlyData = <?php echo json_encode(array_values($hourlyData)); ?>;
    const daysBack = <?php echo $daysBack; ?>;
    const todayDate = '<?php echo $todayDate; ?>';
    const logType = '<?php echo $logTypeFilter; ?>';
    
    const hourlyCtx = document.getElementById('hourlyLineChart').getContext('2d');
    new Chart(hourlyCtx, {
        type: 'line',
        data: {
            labels: Array.from({length: 24}, (_, i) => i.toString().padStart(2, '0') + ':00'),
            datasets: [{
                label: (function() {
                    let prefix = '';
                    if (logType === 'bot') prefix = '🤖 بات‌ها: ';
                    else if (logType === 'nonbot') prefix = '👤 کاربران: ';
                    else prefix = '📊 همه: ';
                    
                    if (daysBack == 1) {
                        return prefix + 'امروز (' + todayDate + ')';
                    } else {
                        return prefix + 'آخرین ' + daysBack + ' روز';
                    }
                })(),
                data: hourlyData,
                borderColor: logType === 'bot' ? '#667eea' : (logType === 'nonbot' ? '#34A853' : '#10B981'),
                backgroundColor: logType === 'bot' ? 'rgba(102, 126, 234, 0.1)' : (logType === 'nonbot' ? 'rgba(52, 168, 83, 0.1)' : 'rgba(16, 185, 129, 0.1)'),
                borderWidth: 3,
                tension: 0.4,
                fill: true,
                pointRadius: 5,
                pointBackgroundColor: logType === 'bot' ? '#667eea' : (logType === 'nonbot' ? '#34A853' : '#10B981')
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: {
                        callback: function(value) { return value.toLocaleString(); }
                    }
                }
            }
        }
    });

    // 4. نمودار Timeline - با فیلتر log_type
    <?php
    $chartDays = min($daysBack, 30);
    $dailyData = [];
    $dates = [];
    
    $dataForTimeline = [];
    if ($logTypeFilter === 'bot') {
        $dataForTimeline = $logs;
    } elseif ($logTypeFilter === 'nonbot') {
        $dataForTimeline = $nonBotLogs;
    } else {
        $dataForTimeline = array_merge($logs, $nonBotLogs);
    }
    
    for ($i = $chartDays - 1; $i >= 0; $i--) {
        $date = date('Y-m-d', strtotime("-$i days"));
        
        if ($chartDays <= 7) {
            $dates[] = date('D j', strtotime($date));
        } else {
            $dates[] = date('M j', strtotime($date));
        }
        
        $count = 0;
        foreach ($dataForTimeline as $log) {
            if ($log['date'] === $date) {
                $count++;
            }
        }
        $dailyData[] = $count;
    }
    
    $timelineLabel = '';
    if ($logTypeFilter === 'bot') {
        $timelineLabel = '🤖 بازدید بات‌ها';
    } elseif ($logTypeFilter === 'nonbot') {
        $timelineLabel = '👤 بازدید کاربران';
    } else {
        $timelineLabel = '📊 کل بازدیدها';
    }
    ?>
    const dailyData = <?php echo json_encode($dailyData); ?>;
    const dateLabels = <?php echo json_encode($dates); ?>;
    
    const dailyCtx = document.getElementById('dailyTimelineChart').getContext('2d');
    new Chart(dailyCtx, {
        type: 'line',
        data: {
            labels: dateLabels,
            datasets: [{
                label: '<?php echo $timelineLabel; ?>',
                data: dailyData,
                borderColor: logType === 'bot' ? '#667eea' : (logType === 'nonbot' ? '#34A853' : '#10B981'),
                backgroundColor: logType === 'bot' ? 'rgba(102, 126, 234, 0.1)' : (logType === 'nonbot' ? 'rgba(52, 168, 83, 0.1)' : 'rgba(16, 185, 129, 0.1)'),
                borderWidth: 3,
                tension: 0.3,
                fill: true,
                pointRadius: 6,
                pointBackgroundColor: logType === 'bot' ? '#667eea' : (logType === 'nonbot' ? '#34A853' : '#10B981')
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: {
                        callback: function(value) { return value.toLocaleString(); }
                    }
                }
            }
        }
    });
    <?php endif; ?>

    // Live Search
    document.getElementById('liveSearch')?.addEventListener('input', function(e) {
        const searchTerm = e.target.value.toLowerCase();
        const logEntries = document.querySelectorAll('.log-entry');
        let visibleCount = 0;

        logEntries.forEach(entry => {
            const text = entry.textContent.toLowerCase();
            if (text.includes(searchTerm)) {
                entry.style.display = '';
                visibleCount++;
            } else {
                entry.style.display = 'none';
            }
        });

        const filteredCountEl = document.getElementById('filteredCount');
        if (filteredCountEl) {
            filteredCountEl.textContent = visibleCount.toLocaleString();
        }
    });

    function resetFilters() {
        window.location.href = '?';
    }

    function exportToExcel() {
        const loadingOverlay = document.getElementById('loadingOverlay');
        if (loadingOverlay) loadingOverlay.style.display = 'flex';
        
        const logEntries = document.querySelectorAll('.log-entry');
        const data = [['ردیف', 'نوع', 'IP', 'تاریخ', 'URL', 'متد', 'کد', 'حجم', 'Referrer', 'User Agent']];
        
        logEntries.forEach((entry, index) => {
            if (entry.style.display !== 'none') {
                const badge = entry.querySelector('.bot-badge')?.textContent.trim() || '';
                const ip = entry.dataset.ip || entry.querySelector('.detail-value')?.textContent.trim() || '';
                const datetime = entry.querySelector('.badge.bg-secondary')?.textContent.replace(/\s+/g, ' ').trim() || '';
                const details = entry.querySelectorAll('.detail-item');
                let url = '', method = '', statusCode = '', bytes = '', referrer = '', userAgent = '';
                
                details.forEach(item => {
                    const label = item.querySelector('.detail-label')?.textContent.trim() || '';
                    const value = item.querySelector('.detail-value')?.textContent.trim() || '';
                    
                    if (label.includes('URL')) url = value;
                    else if (label.includes('حجم')) bytes = value;
                    else if (label.includes('Referrer')) referrer = value;
                    else if (label.includes('User-Agent')) userAgent = value;
                });
                
                method = entry.querySelector('.badge.bg-dark')?.textContent.trim() || '';
                statusCode = entry.querySelector('.status-badge')?.textContent.trim() || '';
                
                data.push([index + 1, badge, ip, datetime, url, method, statusCode, bytes, referrer, userAgent]);
            }
        });
        
        const wb = XLSX.utils.book_new();
        const ws = XLSX.utils.aoa_to_sheet(data);
        ws['!cols'] = [
            { wch: 8 }, { wch: 25 }, { wch: 18 }, { wch: 20 }, { wch: 50 }, 
            { wch: 10 }, { wch: 12 }, { wch: 15 }, { wch: 40 }, { wch: 60 }
        ];
        
        XLSX.utils.book_append_sheet(wb, ws, 'All Logs');
        
        const filename = 'complete_logs_' + new Date().toISOString().slice(0, 10) + '.xlsx';
        XLSX.writeFile(wb, filename);
        
        if (loadingOverlay) loadingOverlay.style.display = 'none';
        
        alert('✅ فایل Excel دانلود شد!\nتعداد: ' + (data.length - 1).toLocaleString() + '\nنام: ' + filename);
    }

    function exportTableToExcel(tableId, filename) {
        const loadingOverlay = document.getElementById('loadingOverlay');
        if (loadingOverlay) loadingOverlay.style.display = 'flex';
        
        setTimeout(() => {
            const table = document.getElementById(tableId);
            if (!table) {
                alert('❌ جدول یافت نشد!');
                if (loadingOverlay) loadingOverlay.style.display = 'none';
                return;
            }
            
            const wb = XLSX.utils.table_to_book(table, { sheet: "Bot Statistics" });
            const ws = wb.Sheets['Bot Statistics'];
            ws['!cols'] = [
                { wch: 25 }, { wch: 15 }, { wch: 18 }, { wch: 15 }, 
                { wch: 15 }, { wch: 15 }, { wch: 18 }, { wch: 18 }, { wch: 18 }
            ];
            
            const finalFilename = filename || ('bot_statistics_' + new Date().toISOString().slice(0, 10) + '.xlsx');
            XLSX.writeFile(wb, finalFilename);
            
            if (loadingOverlay) loadingOverlay.style.display = 'none';
            
            alert('✅ جدول آمار به Excel تبدیل شد!\nنام فایل: ' + finalFilename);
        }, 100);
    }

    function changePageSize(size) {
        const url = new URL(window.location);
        url.searchParams.set('per_page', size);
        url.searchParams.set('page', '1');
        window.location = url;
    }
    </script>

    <script src="https://cdn.sheetjs.com/xlsx-0.19.3/package/dist/xlsx.full.min.js"></script>

</body>
</html>

<?php
if ($analyzer && $autoCleanup && !isset($_GET['cleanup'])) {
    register_shutdown_function(function() use ($analyzer) {
        @$analyzer->cleanup();
    });
}

ob_end_flush();
?>
