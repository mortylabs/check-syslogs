#!/usr/bin/python3
"""
check_syslogs.py — Real-time syslog security monitor with Telegram alerting.

Monitors auth, fail2ban, Home Assistant, UniFi, and nginx container logs using
inotify. Detects SSH attacks, fail2ban bans, HA login attempts, nginx scanner
probes, and suspicious user agents. Sends Telegram alerts with IP geolocation
maps via Google Static Maps API.

Features are toggled via environment variables — no code changes needed between
deployments. See .env.example for full configuration reference.

Requirements:
    pip install -r requirements.txt

Usage:
    python check_syslogs.py
"""

import glob
import logging
import os
import re
import threading
from os import environ, getcwd, path
from sys import exc_info
from time import sleep, time
from urllib.request import urlopen

import inotify.adapters
import requests
import telepot
from dotenv import load_dotenv

# ── Load environment variables ────────────────────────────────────────────────

basedir = path.abspath(path.dirname(__file__))
load_dotenv(path.join(basedir, '.env'))

APPLICATION_NAME = path.basename(__file__).replace(".py", "")

# ── Logging configuration ─────────────────────────────────────────────────────

DIR_LOGS          = environ.get('DIR_LOGS', getcwd())
WRITE_LOG_TO_DISK = environ.get("WRITE_LOG_TO_DISK", "false").lower() == "true"
LOGGING_LEVEL     = logging.getLevelName(environ.get("LOGGING_LEVEL", "INFO").upper())

# ── Telegram ──────────────────────────────────────────────────────────────────

TELEGRAM_ENABLED     = environ.get("TELEGRAM_ENABLED", "false").lower() == "true"
TELEGRAM_BOT_KEY     = environ.get("TELEGRAM_BOT_KEY")
TELEGRAM_BOT_CHAT_ID = environ.get("TELEGRAM_BOT_CHAT_ID")
bot = telepot.Bot(TELEGRAM_BOT_KEY) if (TELEGRAM_ENABLED and TELEGRAM_BOT_KEY) else None

# ── External API keys ─────────────────────────────────────────────────────────

MAPS_API_KEY = environ.get('MAPS_API_KEY')

# ── Feature flags ─────────────────────────────────────────────────────────────

ENABLE_NGINX_MONITOR    = environ.get("ENABLE_NGINX_MONITOR",    "false").lower() == "true"
ENABLE_UNIFI_MONITOR    = environ.get("ENABLE_UNIFI_MONITOR",    "false").lower() == "true"
ENABLE_HA_MONITOR       = environ.get("ENABLE_HA_MONITOR",       "true").lower()  == "true"
ENABLE_FAIL2BAN_MONITOR = environ.get("ENABLE_FAIL2BAN_MONITOR", "true").lower()  == "true"

# ── Log file paths ────────────────────────────────────────────────────────────

LOG_PATH_USER     = environ.get("LOG_PATH_USER",     "/var/log/user.log")
LOG_PATH_AUTH     = environ.get("LOG_PATH_AUTH",     "/var/log/auth.log")
LOG_PATH_FAIL2BAN = environ.get("LOG_PATH_FAIL2BAN", "/var/log/fail2ban.log")
LOG_PATH_HA       = environ.get("LOG_PATH_HA",       "")
LOG_PATH_UNIFI    = environ.get("LOG_PATH_UNIFI",    "")
NGINX_LOG_GLOB    = environ.get("NGINX_LOG_GLOB",    "/var/log/containers/nginx-*_default_nginx-*.log")

# ── IP lookup constants ───────────────────────────────────────────────────────

IP_LOOKUP_API      = "http://ip-api.com/json/"
GOOGLE_MAPS_STATIC = "https://maps.googleapis.com/maps/api/staticmap"

# ── Logging setup ─────────────────────────────────────────────────────────────

def _get_log_filename():
    log_dir = DIR_LOGS
    if not log_dir or not path.isdir(log_dir):
        logging.warning(
            "DIR_LOGS (%s) is invalid or missing, using current working directory (%s)",
            log_dir, getcwd()
        )
        log_dir = getcwd()
    if not log_dir.endswith("/"):
        log_dir += "/"
    return path.join(log_dir, f"{APPLICATION_NAME}.log")


def configure_logging():
    fmt     = '%(asctime)s %(funcName)-20s [%(lineno)s]: %(message)s'
    datefmt = '%Y-%m-%d %H:%M:%S'
    if WRITE_LOG_TO_DISK:
        log_file = _get_log_filename()
        logging.basicConfig(
            format=fmt, datefmt=datefmt,
            filename=log_file, filemode="a",
            level=LOGGING_LEVEL
        )
        print("Logging to", log_file)
    else:
        logging.basicConfig(format=fmt, datefmt=datefmt, level=LOGGING_LEVEL)
    logging.getLogger('inotify.adapters').setLevel(logging.WARNING)
    logging.info("Logger initialised.")


# ── Telegram wrappers ─────────────────────────────────────────────────────────

def _bot_send(fn, *args, **kwargs):
    """Safe Telegram wrapper — swallows send errors to avoid crashing the monitor."""
    if not (TELEGRAM_ENABLED and bot):
        return
    try:
        fn(*args, **kwargs)
    except Exception as e:
        logging.error(f"Telegram send failed: {e}")


def bot_sendMessage(msg):
    _bot_send(
        bot.sendMessage, TELEGRAM_BOT_CHAT_ID,
        f"<b>{APPLICATION_NAME}</b> <i>{msg}</i>",
        parse_mode="Html"
    )


def bot_sendPhoto(photo, caption=''):
    _bot_send(
        bot.sendPhoto, TELEGRAM_BOT_CHAT_ID,
        photo, caption=caption, parse_mode="Markdown"
    )


def send_telegram_with_hdr(hdr, msg, br=False):
    spacing = "\n" if br else " "
    _bot_send(
        bot.sendMessage, TELEGRAM_BOT_CHAT_ID,
        f"<b>{hdr}</b>{spacing}<i>{msg}</i>",
        parse_mode="Html"
    )


def log_error_and_send_telegram(msg):
    logging.exception(msg) if exc_info()[0] else logging.error(msg)
    _bot_send(
        bot.sendMessage, TELEGRAM_BOT_CHAT_ID,
        f"<b>{APPLICATION_NAME}</b> <i>{msg}</i>",
        parse_mode="Html"
    )


# ── Auth/system event patterns ────────────────────────────────────────────────
# List of (compiled_regex, event_label) tuples — order matters, first match wins.

EVENT_PATTERNS = [
    (re.compile(r'vncserver.* connected: (\d+\.\d+\.\d+\.\d+)', re.I),              '✅ VNC connected'),
    (re.compile(r'vncserver.*authenticated: (\d+\.\d+\.\d+\.\d+)', re.I),           '✅ VNC authenticated'),
    (re.compile(r'vncserver.*disconnected: (\d+\.\d+\.\d+\.\d+)', re.I),            '✅ VNC disconnected'),
    (re.compile(r'vncserver.* connected.*from (\d+\.\d+\.\d+\.\d+)', re.I),         '✅ VNC email connected'),
    (re.compile(r'vncserver.*authenticated.*from (\d+\.\d+\.\d+\.\d+)', re.I),      '✅ VNC email authenticated'),
    (re.compile(r'vncserver.*disconnected.*from (\d+\.\d+\.\d+\.\d+)', re.I),       '✅ VNC email disconnected'),
    (re.compile(r'sshd.*Accepted password.*from (\d+\.\d+\.\d+\.\d+)', re.I),       '✅ SSH login'),
    (re.compile(r'sshd.*Failed password.*from (\d+\.\d+\.\d+\.\d+)', re.I),         '❌ SSH failed password'),
    (re.compile(r'fail2ban.*] Ban (\d+\.\d+\.\d+\.\d+)', re.I),                     '🚫 Fail2Ban IP Banned'),
    (re.compile(r'invalid authentication from (\d+\.\d+\.\d+\.\d+)', re.I),         '❌ HA login attempt (IP is Cloudflare proxy — not attacker)'),
    (re.compile(r'Accepted publickey.*from (\d+\.\d+\.\d+\.\d+)', re.I),            '✅ SSH accepted publickey'),
    (re.compile(r'sshd.*Invalid user.*from (\d+\.\d+\.\d+\.\d+)', re.I),            '❌ Invalid user'),
    (re.compile(r'sshd.*authentication failure.*rhost=(\d+\.\d+\.\d+\.\d+)', re.I), '❌ Authentication failure'),
    (re.compile(r'400 POST /api/login', re.I),                                       '❌ Authentication failure'),
    (re.compile(r'banner exchange.*Connection from (\d+\.\d+\.\d+\.\d+)', re.I),    '❌ SSH banner exchange invalid'),
    (re.compile(r'RC=403.*Invalid credential', re.I),                                '❌ UniFi login failed — wrong password'),
    (re.compile(r'RC=429.*Too many requests', re.I),                                 '⚠️ UniFi login — brute force detected'),
    (re.compile(r'RC=423.*Account locked', re.I),                                    '🚨 UniFi account locked — too many attempts'),
    (re.compile(r'Invalid credential', re.I),                                        '❌ Invalid credential (no IP available)'),
]

# Lines to suppress entirely — matched before EVENT_PATTERNS
SUPPRESS_LOG_PATTERNS = re.compile(
    r'kex_exchange_identification.*banner line contains invalid characters'
    r'|Invalid key exists in AuthenticationRequest.*rememberMe',
    re.I
)

# ── Nginx monitoring patterns ─────────────────────────────────────────────────

# Paths that indicate active scanning
SCANNER_PROBE_PATTERNS = re.compile(
    r'(?:'
    r'\.php|\.env|\.git|\.DS_Store|\.htaccess|\.htpasswd|\.config|\.bak|\.sql|\.zip|\.tar'
    r'|wp-admin|wp-login|wp-config|wordpress|xmlrpc'
    r'|/admin|/administrator|/phpmyadmin|/pma|/myadmin'
    r'|/etc/passwd|/proc/self|/shell|/cmd|/exec'
    r'|/config\.json|/config\.yaml|/\.well-known/security'
    r'|/api/v1/pods|/api/v1/secrets'
    r'|/actuator|/actuator/env|/actuator/health'
    r'|/setup\.cgi|/cgi-bin'
    r')',
    re.I
)

# User agents associated with malicious scanners and exploit tools
SUSPICIOUS_UA_PATTERNS = re.compile(
    r'(?:'
    r'sqlmap|nikto|nmap|masscan|zgrab|nuclei|dirbuster|gobuster|wfuzz|ffuf'
    r'|hydra|medusa|burpsuite|metasploit|havij|acunetix|nessus|openvas'
    r'|python-requests/[01]\.|python-urllib|go-http-client/1\.1'
    r'|curl/[0-6]\.|libwww-perl|lwp-trivial'
    r'|zgrab|internet-measurement|censys|shodan'
    r')',
    re.I
)

# Known legitimate bots and monitors to suppress entirely
SUPPRESS_UA_PATTERNS = re.compile(
    r'(?:'
    r'updown\.io|Googlebot|Bingbot|bingbot|Slurp|DuckDuckBot|Baiduspider'
    r'|YandexBot|facebot|ia_archiver|Twitterbot|LinkedInBot'
    r'|AhrefsBot|SemrushBot|MJ12bot|DotBot|BLEXBot'
    r'|PetalBot|Applebot|Discordbot|WhatsApp|Amazonbot'
    r')',
    re.I
)

# nginx container log format parser
# Format: <timestamp> stdout F <nginx_log_line>
# nginx: ip - - [date] "METHOD path HTTP/ver" status size "referer" "ua" "cf-ip"
NGINX_LOG_RE = re.compile(
    r'^\S+\s+stdout\s+F\s+'
    r'(\d+\.\d+\.\d+\.\d+)'           # pod IP (internal)
    r'\s+-\s+-\s+\[.*?\]\s+'
    r'"(\w+)\s+([^\s"]+)\s+HTTP/[\d.]+"\s+'  # method, path
    r'(\d+)\s+\d+\s+'                 # status, bytes
    r'"([^"]*)"\s+'                   # referer (unused)
    r'"([^"]*)"\s+'                   # user agent
    r'"(\d+\.\d+\.\d+\.\d+)"'        # real client IP (Cloudflare header)
)

# ── Fail2ban grace period ─────────────────────────────────────────────────────

last_restart = 0
RESTART_GRACE_PERIOD = 60  # seconds


def mark_fail2ban_restart():
    global last_restart
    last_restart = time()


def is_restart_grace_period():
    return (time() - last_restart) < RESTART_GRACE_PERIOD


# ── IP lookup & geolocation ───────────────────────────────────────────────────

_ip_cache = {}
_external_ip_cache = None


def get_external_ip():
    global _external_ip_cache
    if _external_ip_cache:
        return _external_ip_cache
    try:
        _external_ip_cache = requests.get('https://api.ipify.org', timeout=5).text
        return _external_ip_cache
    except requests.RequestException as e:
        log_error_and_send_telegram(f"External IP retrieval failed: {e}")
        return None


def lookup_ip_location(ip):
    """Look up IP geolocation and send map to Telegram. Non-blocking via thread."""
    threading.Thread(target=_do_ip_lookup, args=(ip,), daemon=True).start()


def _do_ip_lookup(ip):
    if ip in _ip_cache:
        cached = _ip_cache[ip]
        if isinstance(cached, dict):
            now = time()
            if now - cached.get('last_sent', 0) < 30:
                return  # suppress duplicate within 30 seconds
            cached['last_sent'] = now
            bot_sendPhoto(('a.jpg', urlopen(cached['static_img_url'])), cached['caption'])
        return
    try:
        if ip.startswith(("localhost", "127.0.0.1", "192.168.", "10.")):
            ip = get_external_ip()
            if not ip:
                return

        # Try ip-api.com first, fall back to ipinfo.io on failure
        coords, address, isp = None, None, None
        response = requests.get(IP_LOOKUP_API + ip, timeout=5).json()
        if response.get('status') == 'success':
            coords  = f"{response['lat']},{response['lon']}"
            address = f"{response['city']}, {response['regionName']}, {response['country']}"
            isp     = response.get('isp', 'Unknown ISP')
        else:
            logging.warning(f"ip-api failed for {ip}: {response.get('message')}, trying ipinfo.io")
            r2 = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5).json()
            if 'loc' in r2:
                coords  = r2['loc']
                address = f"{r2.get('city', '')}, {r2.get('region', '')}, {r2.get('country', '')}"
                isp     = r2.get('org', 'Unknown ISP')
            else:
                logging.warning(f"ipinfo.io also failed for {ip}")
                _ip_cache[ip] = True
                return

        map_url        = f"https://www.google.com/maps?q={coords}"
        static_img_url = (
            f"{GOOGLE_MAPS_STATIC}?center={coords}&zoom=6"
            f"&size=350x400&maptype=roadmap&key={MAPS_API_KEY}"
            f"&markers=color:red|label:S|{coords}&format=jpg"
        )
        caption = (
            f"```location\n{address}\n{isp}```\n"
            f"[Google Maps]({map_url})\n"
            f"[DB-IP Lookup](https://db-ip.com/{ip})\n"
        )
        _ip_cache[ip] = {'static_img_url': static_img_url, 'caption': caption, 'last_sent': time()}
        bot_sendPhoto(('a.jpg', urlopen(static_img_url)), caption)
    except Exception as e:
        log_error_and_send_telegram(f"IP location lookup failed for {ip}: {e}")


# ── Auth/system log helpers ───────────────────────────────────────────────────

def extract_user_from_line(line):
    patterns = [
        r'invalid user (\w+) from',
        r'password for invalid user (\w+) from',
        r'Failed password for (\w+) from',
        r'Accepted password for (\w+) from',
        r'password for (\w+) from',
        r', as (\w+) ',
        r'user=(\w+)',
        r'user (\w+) permissions',
    ]
    for pattern in patterns:
        match = re.search(pattern, line, re.IGNORECASE)
        if match:
            username = match.group(1).strip()
            return username if is_valid_username(username) else None
    return None


def is_valid_username(user):
    return bool(re.fullmatch(r'\w{2,20}', user))


def extract_ip(line):
    match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
    return match.group(1) if match else None


# ── Nginx log processing ──────────────────────────────────────────────────────

def process_nginx_line(line):
    """Parse and evaluate a single nginx container log line."""
    m = NGINX_LOG_RE.match(line)
    if not m:
        return

    _pod_ip, method, req_path, status, _referer, user_agent, client_ip = m.groups()
    status = int(status)

    if SUPPRESS_UA_PATTERNS.search(user_agent):
        return

    if SCANNER_PROBE_PATTERNS.search(req_path):
        send_telegram_with_hdr(
            hdr=f"🔍 Scanner probe — {method} {req_path}",
            msg=f"Status: {status}\nIP: {client_ip}\nUA: {user_agent}"
        )
        lookup_ip_location(client_ip)
        return

    if status == 404 and SUSPICIOUS_UA_PATTERNS.search(user_agent):
        send_telegram_with_hdr(
            hdr=f"⚠️ Suspicious UA — 404 {req_path}",
            msg=f"IP: {client_ip}\nUA: {user_agent}"
        )
        lookup_ip_location(client_ip)
        return


def find_nginx_log():
    """Resolve the current nginx container log path from glob."""
    matches = glob.glob(NGINX_LOG_GLOB)
    return matches[0] if matches else None


def monitor_nginx_log():
    """Monitor nginx container log. Handles pod restarts by re-resolving the log path."""
    logging.info("nginx monitor starting...")
    retry_count = 0

    while True:
        logfile = find_nginx_log()

        if not logfile:
            retry_count += 1
            if retry_count > 6:
                log_error_and_send_telegram("nginx container log not found!")
                retry_count = 0
            sleep(10)
            continue

        retry_count = 0
        logging.info(f"nginx monitor: found log at {logfile}")
        notifier = inotify.adapters.Inotify()

        try:
            with open(logfile, 'r') as log_src:
                log_src.seek(0, os.SEEK_END)
                notifier.add_watch(logfile)

                for event in notifier.event_gen(yield_nones=False):
                    (_, types, _, _) = event

                    if 'IN_MOVE_SELF' in types or 'IN_DELETE_SELF' in types:
                        logging.info("nginx log moved/deleted (pod restart?), re-resolving...")
                        notifier.remove_watch(logfile)
                        sleep(5)
                        break

                    if 'IN_MODIFY' in types:
                        for line in log_src:
                            process_nginx_line(line)

        except Exception as e:
            log_error_and_send_telegram(f"nginx monitor error: {e}")
            sleep(2)


# ── Auth/system log processing ────────────────────────────────────────────────

def process_log_line(logfile, line, error_keywords):
    if SUPPRESS_LOG_PATTERNS.search(line):
        return

    if "fail2ban" in logfile:
        if "Shutdown in progress" in line or "Starting Fail2ban" in line:
            logging.info(f"fail2ban restart suppression: {line.strip()}")
            mark_fail2ban_restart()
            return
        if "Restore Ban" in line:
            logging.info(f"Suppressed Restore Ban: {line.strip()}")
            return
        if "Unban" in line and is_restart_grace_period():
            logging.info(f"Suppressed expected unban during grace: {line.strip()}")
            return
        if "Flush ticket(s)" in line:
            return

    # Only process lines containing at least one monitored keyword
    if not any(kw in line.lower() for kw in error_keywords):
        return

    any_pattern_match = False
    for pattern, event in EVENT_PATTERNS:
        match = pattern.search(line)
        if match:
            any_pattern_match = True
            ip        = match.group(1) if match.groups() else extract_ip(line)
            user      = extract_user_from_line(line)
            user_info = f" ({user})" if user else ""
            caption   = f"{event}{user_info}\n"

            if ip:
                send_telegram_with_hdr(hdr=caption, msg=f"{logfile}\n{ip}\n")
                lookup_ip_location(ip)
            else:
                send_telegram_with_hdr(hdr=caption, msg=f"{logfile}\n")
                line_cleaned = line.replace("<", "").replace(">", "")
                send_telegram_with_hdr(
                    hdr=f"⚠️ {logfile}\n",
                    msg=f"IP extraction failed\nLine: {line_cleaned}"
                )

    if not any_pattern_match:
        send_telegram_with_hdr(hdr=f"⚠️ {logfile}\n", msg=f"{line}\n")


def monitor_log_file(logfile, error_keywords):
    retry_count = 0

    while True:
        notifier = inotify.adapters.Inotify()
        try:
            if not os.path.exists(logfile):
                retry_count += 1
                if retry_count > 6:
                    log_error_and_send_telegram(f"{logfile} not found!")
                sleep(10)
                continue

            logging.info(f"found {logfile}, opening...")
            retry_count = 0

            with open(logfile, 'r') as log_src:
                log_src.seek(0, os.SEEK_END)
                notifier.add_watch(logfile)

                for event in notifier.event_gen(yield_nones=False):
                    (_, types, _, _) = event
                    if 'IN_MOVE_SELF' in types:
                        logging.info(f"{logfile} moved, restarting monitor.")
                        notifier.remove_watch(logfile)
                        break
                    if 'IN_MODIFY' in types:
                        for line in log_src:
                            process_log_line(logfile, line, error_keywords)

        except Exception as e:
            log_error_and_send_telegram(f"Monitoring error in {logfile}: {e}")
            sleep(2)


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    configure_logging()
    threads = []

    log_keywords = {
        LOG_PATH_USER: ["connected", "authenticated", "disconnected from"],
        LOG_PATH_AUTH: ["fail", "denied", "error", "accepted", "disconnect from",
                        "invalid", "authenticating", "failed password",
                        "password changed", "could not identify password", "logged out",
                        "banner exchange"],
    }

    if ENABLE_FAIL2BAN_MONITOR and LOG_PATH_FAIL2BAN:
        log_keywords[LOG_PATH_FAIL2BAN] = ["ban", "found", "exiting fail2ban", "starting fail2ban"]

    if ENABLE_HA_MONITOR and LOG_PATH_HA:
        log_keywords[LOG_PATH_HA] = ["invalid authentication from"]

    if ENABLE_UNIFI_MONITOR and LOG_PATH_UNIFI:
        log_keywords[LOG_PATH_UNIFI] = [
            "login", "invalid credential", "RC=403", "RC=429", "RC=423", "failed to authenticate"
        ]

    for logfile, keywords in log_keywords.items():
        if not logfile:
            continue
        t = threading.Thread(target=monitor_log_file, args=(logfile, keywords), daemon=True)
        t.start()
        threads.append(t)

    if ENABLE_NGINX_MONITOR:
        t = threading.Thread(target=monitor_nginx_log, daemon=True)
        t.start()
        threads.append(t)

    send_telegram_with_hdr(hdr="🕵 Log Monitoring started", msg="")

    for thread in threads:
        thread.join()


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        log_error_and_send_telegram(f"Fatal error: {e}")
        raise
