# check-syslogs

[![Python Version](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

**check_syslogs.py** is a real-time Linux syslog security monitor that watches your auth, fail2ban, Home Assistant, UniFi, and nginx logs using inotify — sending instant Telegram alerts with IP geolocation maps when suspicious activity is detected.

Developed for a Raspberry Pi homelab running Home Assistant, a private web presence behind Cloudflare, and multiple IoT devices — this script provides 24/7 visibility into:

- 🔑 **SSH and VNC access** — every login, failed attempt, and banned IP on the Pi itself
- 🏠 **Home Assistant** — invalid authentication attempts from the internet
- 🌐 **nginx / Cloudflare** — scanner probes, exploit attempts, and suspicious user agents targeting your public web presence
- 🚫 **fail2ban** — real-time ban notifications with attacker geolocation maps sent straight to Telegram

No cloud dependency, no subscription — just a lightweight Python daemon running on the Pi, alerting you the moment something happens.

---

## 📌 Key Benefit

🔐 **Single daemon, full visibility** — instead of manually tailing logs across multiple files, this script monitors all your security-relevant logs simultaneously in background threads, alerting you the moment something happens — SSH attacks, fail2ban bans, HA login attempts, nginx scanner probes, and more.

🗺️ **IP geolocation on every alert** — every suspicious IP triggers an automatic Google Maps image sent via Telegram, showing the attacker's location, ISP, and a DB-IP lookup link.

🎛️ **Feature-flag driven** — enable only the monitors relevant to your deployment via `.env`. No code changes needed between different hosts (e.g. UK vs SA instances).

---

## 📖 Table of Contents

- [Features](#features)
- [Quickstart](#quickstart)
- [Configuration](#configuration)
- [Monitored Events](#monitored-events)
- [Systemctl Service](#systemctl-service)
- [Roadmap](#roadmap)
- [License](#license)

---

## 🧩 Features

- Real-time monitoring via inotify — zero polling overhead
- Monitors auth, fail2ban, Home Assistant, UniFi, and nginx container logs
- Detects SSH attacks, fail2ban bans, VNC connections, HA login attempts
- nginx scanner probe detection with path and user-agent matching
- IP geolocation via ip-api.com with ipinfo.io fallback
- Google Static Maps image sent to Telegram for every suspicious IP
- Fail2ban grace period — suppresses noisy unban alerts on restart
- Handles log rotation and k3s pod restarts gracefully
- Feature flags — toggle monitors per deployment via `.env`
- Lightweight — runs on a Raspberry Pi, no container needed

---

## 🚀 Quickstart

```bash
git clone https://github.com/mortylabs/check-syslogs.git
cd check-syslogs
cp .env.example .env
nano .env  # configure Telegram, Maps API key, and feature flags
pip install -r requirements.txt
python check_syslogs.py
```

---

## ⚙️ Configuration

Create and customise a `.env` file in the project root:

```bash
cp .env.example .env
```

| Variable | Description | Default |
|---|---|---|
| `WRITE_LOG_TO_DISK` | Write logs to file or stdout | `false` |
| `LOGGING_LEVEL` | Log level (`DEBUG`, `INFO`, `WARN`, `ERROR`) | `INFO` |
| `DIR_LOGS` | Directory for log file output | current dir |
| `TELEGRAM_ENABLED` | Enable Telegram alerts | `false` |
| `TELEGRAM_BOT_KEY` | Telegram bot token from BotFather | — |
| `TELEGRAM_BOT_CHAT_ID` | Telegram chat ID to send alerts to | — |
| `MAPS_API_KEY` | Google Maps Static API key for geolocation maps | — |
| `ENABLE_NGINX_MONITOR` | Monitor nginx container logs (k3s) | `false` |
| `ENABLE_UNIFI_MONITOR` | Monitor UniFi controller logs | `false` |
| `ENABLE_HA_MONITOR` | Monitor Home Assistant logs | `true` |
| `ENABLE_FAIL2BAN_MONITOR` | Monitor fail2ban logs | `true` |
| `LOG_PATH_USER` | Path to user.log | `/var/log/user.log` |
| `LOG_PATH_AUTH` | Path to auth.log | `/var/log/auth.log` |
| `LOG_PATH_FAIL2BAN` | Path to fail2ban.log | `/var/log/fail2ban.log` |
| `LOG_PATH_HA` | Path to Home Assistant log | — |
| `LOG_PATH_UNIFI` | Path to UniFi server log | — |
| `NGINX_LOG_GLOB` | Glob pattern for nginx container log | `/var/log/containers/nginx-*` |

---

## 🔍 Monitored Events

### Auth / System logs
| Event | Alert |
|---|---|
| SSH login (password or pubkey) | ✅ |
| SSH failed password | ❌ |
| SSH invalid user | ❌ |
| SSH banner exchange invalid | ❌ |
| VNC connect / authenticate / disconnect | ✅ |
| fail2ban IP banned | 🚫 |
| HA invalid authentication | ❌ |
| UniFi login failed (403/429/423) | ❌ |

### nginx container logs
| Event | Alert |
|---|---|
| Scanner probe paths (`.php`, `.env`, `wp-admin`, k8s endpoints etc.) | 🔍 |
| Suspicious user agents (sqlmap, nikto, nuclei, masscan etc.) | ⚠️ |
| Known good bots (Googlebot, UptimeRobot etc.) | suppressed |

---

## 🚁 Systemctl Service

To run as a background service that starts on boot:

```bash
sudo nano /etc/systemd/system/check_syslog.service
```

```ini
[Unit]
Description=check_syslogs security monitor
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /home/pi/check-syslogs/check_syslogs.py
Restart=always
RestartSec=5
User=pi
Group=pi

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable check_syslog
sudo systemctl start check_syslog
```

---

## 📈 Roadmap

- [x] Real-time inotify-based log monitoring
- [x] Telegram alerting with IP geolocation maps
- [x] fail2ban grace period suppression
- [x] nginx container log monitoring with scanner detection
- [x] Feature-flag driven deployment
- [x] ip-api.com with ipinfo.io fallback
- [ ] IPv6 support
- [ ] Configurable alert rate limiting per IP
- [ ] Webhook support (Slack, Discord) as alternative to Telegram

---

## 📜 License

This project is licensed under the MIT License.
See the [LICENSE](LICENSE) file for details.

---

## 💬 Questions?

Have feedback or need support?

- Open an [issue](https://github.com/mortylabs/check-syslogs/issues)
- Start a discussion on the repo
- Suggest features or improvements via pull requests
