import os
import sys
import time
import base64
import argparse
import threading
import warnings
import signal
import secrets
import string
import socket
import logging
import gc
import hashlib
import re
import io
import html
import math
import json
import queue
import ipaddress
from urllib.parse import urlparse, urljoin
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

MISSING_DEPENDENCIES = []

try:
    import imagehash
except ImportError:
    imagehash = None
    MISSING_DEPENDENCIES.append("imagehash")

try:
    import requests
except ImportError:
    requests = None
    MISSING_DEPENDENCIES.append("requests")

try:
    import urllib3
except ImportError:
    urllib3 = None
    MISSING_DEPENDENCIES.append("urllib3")

try:
    from PIL import Image
except ImportError:
    Image = None
    MISSING_DEPENDENCIES.append("Pillow")

try:
    from tqdm import tqdm
except ImportError:
    class tqdm:
        def __init__(self, total=None, desc=None, unit=None, bar_format=None):
            self.total = total or 0
            self.n = 0
            if desc:
                print(f"[*] {desc}: {self.total} {unit or 'items'}")
        def update(self, n=1):
            self.n += n
        def write(self, message):
            print(message)
        def close(self):
            pass

try:
    from bs4 import BeautifulSoup, XMLParsedAsHTMLWarning
except ImportError:
    BeautifulSoup = None
    XMLParsedAsHTMLWarning = UserWarning
    MISSING_DEPENDENCIES.append("beautifulsoup4")

try:
    from flask import Flask, request, session, redirect, send_from_directory
except ImportError:
    Flask = request = session = redirect = send_from_directory = None
    MISSING_DEPENDENCIES.append("flask")

try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.chrome.service import Service
    from selenium.common.exceptions import TimeoutException, WebDriverException
except ImportError:
    webdriver = Options = Service = None
    class TimeoutException(Exception):
        pass
    class WebDriverException(Exception):
        pass
    MISSING_DEPENDENCIES.append("selenium")

try:
    from webdriver_manager.chrome import ChromeDriverManager
except ImportError:
    ChromeDriverManager = None
    MISSING_DEPENDENCIES.append("webdriver-manager")

try:
    from Wappalyzer import Wappalyzer, WebPage
except ImportError:
    Wappalyzer = WebPage = None
    MISSING_DEPENDENCIES.append("python-Wappalyzer")

# --- Global Configurations & Warnings ---
if urllib3:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)
warnings.filterwarnings("ignore", category=UserWarning)

# Unified Branding
APP_NAME = "AssetScanner Pro"
VERSION = "v2.0 Comprehensive & Powerful Edition"
TAGLINE = "Visual Intelligence & Smart Asset Correlation"
ATTRIBUTION_NAME = "BimBox"
ATTRIBUTION_URL = "https://github.com/BimBoxH4"

BANNER = rf"""
+------------------------------------------------------------------------------+
|                                                                              |
|      ___                   __   _____                                         |
|     /   |  _____________  / /_ / ___/_________ _____  ____  ___  _____        |
|    / /| | / ___/ ___/ _ \/ __/ \__ \/ ___/ __ `/ __ \/ __ \/ _ \/ ___/        |
|   / ___ |(__  |__  )  __/ /_  ___/ / /__/ /_/ / / / / / / /  __/ /           |
|  /_/  |_/____/____/\___/\__/ /____/\___/\__,_/_/ /_/_/ /_/\___/_/            |
|                                                                              |
|{APP_NAME:^78}|
|{VERSION:^78}|
|{TAGLINE:^78}|
|                                                                              |
|{f"Attribution: {ATTRIBUTION_NAME} | {ATTRIBUTION_URL}":^78}|
|                                                                              |
+------------------------------------------------------------------------------+
"""

USAGE_GUIDE = f"""
{BANNER}
DESCRIPTION:
    AssetScanner Pro captures web assets with a headless browser, fingerprints
    device products, hashes screenshots/icons/DOM/text, groups similar assets,
    and generates an interactive HTML report.

COMMON EXAMPLES:
    Scan one target:
        python v3.py -u https://example.com

    Scan targets from a file and save a report:
        python v3.py -f targets.txt -r report.html

    Low-resource scan mode:
        python v3.py -f targets.txt --fast -t 1 --timeout 20 --render-wait 0.2 --retries 1

    Full scan with fewer browser workers:
        python v3.py -f targets.txt -t 2 --timeout 35

    Serve an existing report securely:
        python v3.py --server 127.0.0.1:8080 -r report.html

NOTES:
    Use --fast on low-configuration servers to skip optional enrichment.
    Press Ctrl+C during scanning to choose whether to stop and save a partial report.
"""

CHROME_DRIVER_PATH = None
WAPPALYZER_INST = None
GEO_CACHE = {}
HOST_GEO_CACHE = {}
DEFAULT_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
DEFAULT_FINGERPRINT_DB = "asset_fingerprints.json"
FINGERPRINT_CACHE_TTL = 7 * 24 * 60 * 60
DEFAULT_FINGERPRINT_URLS = [
    "https://raw.githubusercontent.com/0x727/FingerprintHub/main/web_fingerprint_v3.json",
    "https://raw.githubusercontent.com/0x727/FingerprintHub/main/web_fingerprint.json",
]
GROUP_SCORE_THRESHOLD = 55
MAX_GROUP_REPRESENTATIVES = 4
LOGIN_MAX_FAILURES = 5
LOGIN_LOCKOUT_SECONDS = 60
CMS_EXCLUSIONS = {
    "wordpress", "drupal", "joomla", "magento", "shopify", "wix", "squarespace",
    "typo3", "ghost", "blogger", "prestashop", "opencart"
}
WEB_APP_PRODUCT_EXCLUSIONS = CMS_EXCLUSIONS | {
    "apache", "nginx", "iis", "php", "java", "jquery", "bootstrap", "react", "vue",
    "angular", "laravel", "thinkphp", "spring", "struts", "tomcat", "jenkins",
    "grafana", "kibana", "elasticsearch", "prometheus", "zabbix", "phpmyadmin",
    "adminer", "gitlab", "jira", "confluence", "discuz", "dedecms", "metinfo",
    "empirecms", "typecho", "zblog", "ecshop", "seeyon", "泛微", "致远"
}
HARDWARE_PRODUCT_KEYWORDS = {
    "fortinet", "fortigate", "fortiweb", "fortimail", "fortiauthenticator", "citrix",
    "netscaler", "adc", "f5", "big-ip", "bigip", "tmui", "cisco", "asa", "meraki",
    "palo alto", "globalprotect", "sonicwall", "sophos", "check point", "juniper",
    "pulse secure", "mikrotik", "routeros", "ubiquiti", "unifi", "pfsense", "openwrt",
    "luci", "vmware", "vcenter", "esxi", "proxmox", "idrac", "ilo", "ipmi",
    "supermicro", "synology", "qnap", "hikvision", "dahua", "huawei", "h3c", "zte",
    "sangfor", "ruijie", "aruba", "tp-link", "d-link", "netgear", "router", "firewall",
    "gateway", "vpn", "waf", "switch", "nas", "camera", "nvr", "dvr", "bmc",
    "深信服", "锐捷", "海康", "海康威视", "大华", "华为", "新华三", "网关", "防火墙", "交换机", "路由"
}
DEVICE_PRODUCT_RULES = [
    ("Fortinet FortiGate", [(r"\bfortigate\b", 6), (r"fortinet.*ssl-vpn", 5), (r"/remote/login", 4), (r"/sslvpn/", 4), (r"fortinet", 2)]),
    ("Fortinet FortiWeb", [(r"\bfortiweb\b", 7), (r"fortiweb login", 7), (r"fortinet", 2)]),
    ("Fortinet FortiMail", [(r"\bfortimail\b", 7), (r"fortimail login", 7), (r"fortinet", 2)]),
    ("Fortinet FortiAuthenticator", [(r"fortiauthenticator", 8), (r"fortinet", 2)]),
    ("Citrix ADC/Gateway", [(r"citrix gateway", 7), (r"netscaler", 7), (r"gateway\.ns", 7), (r"/vpn/index\.html", 5), (r"/logon/LogonPoint", 5), (r"citrix", 3)]),
    ("Cisco ASA", [(r"adaptive security appliance", 8), (r"asa firewall", 8), (r"webvpn", 5), (r"cisco secure desktop", 5), (r"cisco", 2)]),
    ("Cisco IOS/Router", [(r"cisco ios", 7), (r"cisco router", 6), (r"cisco configuration", 5), (r"cisco", 2)]),
    ("Cisco Meraki", [(r"meraki", 8), (r"cisco meraki", 8)]),
    ("Palo Alto GlobalProtect", [(r"globalprotect", 8), (r"palo alto networks", 6), (r"pan-os", 6), (r"/global-protect/", 5)]),
    ("F5 BIG-IP", [(r"big-ip", 8), (r"\btmui\b", 7), (r"configuration utility", 5), (r"f5 networks", 5)]),
    ("SonicWall", [(r"sonicwall", 7), (r"network security appliance", 5), (r"virtual office", 4)]),
    ("Sophos Firewall", [(r"sophos firewall", 8), (r"sophos user portal", 7), (r"sophos webadmin", 7), (r"\bsophos\b", 3)]),
    ("Check Point Gaia", [(r"gaia portal", 8), (r"check point", 6), (r"smartconsole", 5)]),
    ("Juniper Secure Access", [(r"juniper secure access", 8), (r"\bjunos\b", 6), (r"pulse secure", 6), (r"juniper networks", 5)]),
    ("MikroTik RouterOS", [(r"routeros", 8), (r"webfig", 8), (r"mikrotik", 6)]),
    ("Ubiquiti UniFi", [(r"unifi", 8), (r"ubiquiti", 6), (r"airmax", 5), (r"edgeos", 5)]),
    ("pfSense", [(r"pfsense", 8)]),
    ("OpenWrt LuCI", [(r"openwrt", 8), (r"luci - lua configuration interface", 8), (r"cgi-bin/luci", 7)]),
    ("VMware vCenter", [(r"vcenter", 8), (r"vsphere client", 8), (r"vmware", 3)]),
    ("VMware ESXi", [(r"esxi", 8), (r"vmware host client", 8), (r"vmware", 3)]),
    ("Proxmox VE", [(r"proxmox", 8), (r"pve manager", 8)]),
    ("Dell iDRAC", [(r"idrac", 8), (r"integrated dell remote access", 8)]),
    ("HP iLO", [(r"integrated lights-out", 8), (r"hewlett packard enterprise", 5), (r"\bilo\b", 5)]),
    ("Supermicro IPMI", [(r"supermicro", 5), (r"ipmi", 6), (r"baseboard management controller", 8)]),
    ("Synology DSM", [(r"synology", 7), (r"diskstation", 7), (r"\bdsm\b", 5)]),
    ("QNAP QTS", [(r"\bqnap\b", 7), (r"qts login", 8)]),
    ("Hikvision", [(r"hikvision", 8), (r"海康威视", 8)]),
    ("Dahua", [(r"\bdahua\b", 8), (r"大华", 8)]),
    ("Huawei Device", [(r"huawei technologies", 6), (r"\bhuawei\b", 4), (r"esight", 6)]),
    ("H3C Device", [(r"h3c technologies", 7), (r"\bh3c\b", 6)]),
    ("ZTE Device", [(r"zte corporation", 7), (r"\bzte\b", 5)]),
    ("Sangfor", [(r"sangfor", 7), (r"深信服", 8)]),
    ("Ruijie", [(r"ruijie", 7), (r"锐捷", 8)]),
    ("Aruba", [(r"aruba networks", 7), (r"aruba instant", 8)]),
    ("TP-Link", [(r"tp-link", 7), (r"tplink", 6)]),
    ("D-Link", [(r"d-link", 7), (r"dlink", 6)]),
    ("Netgear", [(r"netgear", 7)]),
]
PRODUCT_PRIORITY = {
    "Citrix ADC/Gateway": 10,
    "F5 BIG-IP": 20,
    "Fortinet FortiGate": 30,
    "Fortinet FortiWeb": 31,
    "Fortinet FortiMail": 32,
    "Fortinet FortiAuthenticator": 33,
    "Palo Alto GlobalProtect": 40,
    "Cisco ASA": 50,
    "Cisco IOS/Router": 51,
    "Cisco Meraki": 52,
    "SonicWall": 60,
    "Sophos Firewall": 61,
    "Check Point Gaia": 62,
    "Juniper Secure Access": 63,
    "VMware vCenter": 80,
    "VMware ESXi": 81,
    "Proxmox VE": 82,
    "Dell iDRAC": 90,
    "HP iLO": 91,
    "Supermicro IPMI": 92,
}
PRODUCT_PRIORITY_KEYWORDS = [
    ("citrix", 10), ("netscaler", 10), ("f5", 20), ("big-ip", 20), ("bigip", 20),
    ("fortigate", 30), ("fortiweb", 31), ("fortimail", 32), ("fortinet", 33),
    ("palo alto", 40), ("globalprotect", 40), ("cisco", 50), ("sonicwall", 60),
    ("sophos", 61), ("check point", 62), ("juniper", 63), ("mikrotik", 70),
    ("ubiquiti", 71), ("unifi", 71), ("pfsense", 72), ("openwrt", 73),
    ("vmware", 80), ("vcenter", 80), ("esxi", 81), ("proxmox", 82),
    ("idrac", 90), ("ilo", 91), ("ipmi", 92), ("supermicro", 92),
    ("synology", 100), ("qnap", 101), ("hikvision", 110), ("海康", 110),
    ("dahua", 111), ("大华", 111), ("huawei", 120), ("华为", 120),
    ("h3c", 121), ("新华三", 121), ("zte", 122), ("sangfor", 130),
    ("深信服", 130), ("ruijie", 131), ("锐捷", 131), ("aruba", 132),
    ("tp-link", 140), ("d-link", 141), ("netgear", 142),
]
NORMALIZE_URL_RE = re.compile(r"https?://\S+")
NORMALIZE_HEX_RE = re.compile(r"\b[0-9a-f]{8,}\b")
NORMALIZE_DIGITS_RE = re.compile(r"\d+")
NORMALIZE_SPACE_RE = re.compile(r"\s+")
PATH_HEX_RE = re.compile(r"[0-9a-f]{8,}")
LITERAL_UNESCAPE_RE = re.compile(r"\\([/._:;?=&-])")
LITERAL_STRIP_RE = re.compile(r"[\^$+?{}\[\]()]" )

class UltraScanner:
    def __init__(self, args, pbar=None):
        self.args = args
        self.results = []
        self.ip_ports = defaultdict(set) 
        self.shodan_cache = {}
        self.lock = threading.Lock()
        self.thread_local = threading.local()
        self.is_running = True 
        self.pbar = pbar
        self.device_rules = list(DEVICE_PRODUCT_RULES)
        self.compiled_device_rules = []
        self.product_priority = dict(PRODUCT_PRIORITY)
        self.external_products = set()
        self.shodan_enriched = False
        
        report_abs = os.path.abspath(self.args.report)
        self.report_dir = report_abs if os.path.isdir(report_abs) else os.path.dirname(report_abs)
        self.assets_dirname = f"{os.path.splitext(os.path.basename(self.args.report))[0]}_assets"
        self.assets_path = os.path.join(self.report_dir, self.assets_dirname)
        
        if not os.path.exists(self.assets_path):
            os.makedirs(self.assets_path, exist_ok=True)

        self.auto_refresh_fingerprint_library()
        self.load_fingerprint_library()
        self.compile_device_rules()

    def log(self, message):
        if self.pbar: self.pbar.write(message)
        else: print(message)

    def fingerprint_db_path(self):
        path = getattr(self.args, 'fingerprints', None) or DEFAULT_FINGERPRINT_DB
        return os.path.abspath(path)

    def fingerprint_urls(self):
        url = getattr(self.args, 'fingerprints_url', None)
        if url:
            return [url]
        return list(DEFAULT_FINGERPRINT_URLS)

    def fingerprint_data_sha256(self, data):
        encoded = json.dumps(data, sort_keys=True, ensure_ascii=False).encode('utf-8')
        return hashlib.sha256(encoded).hexdigest()

    def normalize_product_name(self, product):
        return re.sub(r"\s+", " ", str(product or "").lower()).strip()

    def is_hardware_product_name(self, product):
        normalized = self.normalize_product_name(product)
        if not normalized:
            return False
        if any(excluded in normalized for excluded in WEB_APP_PRODUCT_EXCLUSIONS):
            return False
        return any(keyword in normalized for keyword in HARDWARE_PRODUCT_KEYWORDS)

    def priority_from_product_name(self, product):
        normalized = self.normalize_product_name(product)
        if not normalized:
            return 100000
        for keyword, priority in PRODUCT_PRIORITY_KEYWORDS:
            if keyword in normalized:
                return priority
        return 5000 if self.is_hardware_product_name(product) else 100000

    def fingerprint_cache_stale(self):
        path = self.fingerprint_db_path()
        if not os.path.exists(path):
            return True
        try:
            return (time.time() - os.path.getmtime(path)) > FINGERPRINT_CACHE_TTL
        except:
            return True

    def auto_refresh_fingerprint_library(self):
        if getattr(self.args, 'no_auto_fingerprints', False):
            return
        if getattr(self.args, 'update_fingerprints', False) or getattr(self.args, 'check_fingerprints_update', False):
            return
        if self.fingerprint_cache_stale():
            self.update_fingerprint_library(silent=True)

    def fetch_remote_fingerprint_data(self, silent=False):
        for url in self.fingerprint_urls():
            try:
                r = requests.get(url, timeout=20, headers={'User-Agent': DEFAULT_UA})
                r.raise_for_status()
                data = r.json()
                loaded = self.parse_fingerprint_library(data)
                if loaded:
                    if not silent:
                        self.log(f"[*] Fetched {len(loaded)} fingerprint rules from {url}")
                    return data
                if not silent:
                    self.log(f"[!] Remote fingerprint data has no usable rules: {url}")
            except Exception as e:
                if not silent:
                    self.log(f"[!] Failed fingerprint source {url}: {str(e)[:100]}")
        return None

    def update_fingerprint_library(self, check_only=False, silent=False):
        remote_data = self.fetch_remote_fingerprint_data(silent=silent)
        if remote_data is None:
            if not silent:
                self.log("[!] No online fingerprint database could be fetched; built-in/local rules will be used")
            return False

        path = self.fingerprint_db_path()
        remote_hash = self.fingerprint_data_sha256(remote_data)
        local_hash = ""
        if os.path.exists(path):
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    local_hash = self.fingerprint_data_sha256(json.load(f))
            except:
                local_hash = "invalid"

        if local_hash == remote_hash:
            if not silent:
                self.log("[*] Fingerprint database is already up to date")
            return True
        if check_only:
            if not silent:
                self.log("[*] Fingerprint database update available")
            return True

        try:
            parent = os.path.dirname(path)
            if parent:
                os.makedirs(parent, exist_ok=True)
            tmp_path = path + ".tmp"
            with open(tmp_path, 'w', encoding='utf-8') as f:
                json.dump(remote_data, f, ensure_ascii=False, indent=2)
            os.replace(tmp_path, path)
            if not silent:
                self.log(f"[+] Fingerprint database updated: {path}")
            return True
        except Exception as e:
            if not silent:
                self.log(f"[!] Failed to save fingerprint database: {str(e)[:100]}")
            return False

    def load_fingerprint_library(self):
        path = self.fingerprint_db_path()
        if not os.path.exists(path):
            return
        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            loaded = self.parse_fingerprint_library(data)
            if loaded:
                self.device_rules.extend(loaded)
                self.external_products.update(product for product, _ in loaded)
                self.log(f"[*] Loaded {len(loaded)} external fingerprint rules")
            else:
                self.log(f"[!] Fingerprint library has no usable rules: {path}")
        except Exception as e:
            self.log(f"[!] Failed to load fingerprint library: {str(e)[:80]}")

    def compile_device_rules(self):
        compiled_rules = []
        for product, patterns in self.device_rules:
            if not self.is_hardware_product_name(product):
                continue
            compiled_patterns = []
            for pattern, weight in patterns:
                raw_pattern = str(pattern or "")
                if not raw_pattern:
                    continue
                try:
                    compiled_patterns.append((raw_pattern, weight, re.compile(raw_pattern, re.I), ""))
                except re.error:
                    literal = LITERAL_UNESCAPE_RE.sub(r"\1", raw_pattern).lower()
                    literal = literal.replace(".*", " ").replace("\\", "")
                    literal = LITERAL_STRIP_RE.sub("", literal).strip()
                    if literal:
                        compiled_patterns.append((raw_pattern, weight, None, literal))
            if compiled_patterns:
                compiled_rules.append((product, compiled_patterns))
        self.compiled_device_rules = compiled_rules

    def parse_fingerprint_library(self, data):
        if not isinstance(data, (list, dict)):
            return []

        records = data if isinstance(data, list) else data.get('products') or data.get('fingerprints') or data.get('apps') or []
        if isinstance(data, dict) and not records:
            records = [{"product": k, "patterns": v} for k, v in data.items() if isinstance(v, (list, dict))]

        parsed = []
        for record in records:
            if not isinstance(record, dict):
                continue
            product = record.get('product') or record.get('name') or record.get('cms') or record.get('app')
            if not product:
                continue
            if not self.is_hardware_product_name(product):
                continue

            priority = record.get('priority')
            if isinstance(priority, int):
                self.product_priority[product] = priority
            else:
                derived_priority = self.priority_from_product_name(product)
                if derived_priority < 100000:
                    self.product_priority[product] = derived_priority

            raw_patterns = (
                record.get('patterns') or record.get('regex') or record.get('keywords') or
                record.get('keyword') or record.get('rules') or record.get('matchers') or []
            )
            extra_patterns = []
            for key in ('body', 'title', 'headers', 'header', 'html', 'script', 'scripts', 'url', 'path'):
                value = record.get(key)
                if isinstance(value, dict):
                    extra_patterns.extend(str(v) for v in value.values())
                elif isinstance(value, list):
                    extra_patterns.extend(value)
                elif value:
                    extra_patterns.append(value)

            if isinstance(raw_patterns, (str, int, float)):
                raw_patterns = [raw_patterns]
            if isinstance(raw_patterns, dict):
                collected = []
                for key in ('body', 'title', 'header', 'headers', 'html', 'script', 'scripts', 'url', 'all'):
                    value = raw_patterns.get(key)
                    if isinstance(value, dict):
                        collected.extend(str(v) for v in value.values())
                    elif isinstance(value, list):
                        collected.extend(value)
                    elif value:
                        collected.append(value)
                raw_patterns = collected
            raw_patterns = list(raw_patterns) + extra_patterns

            patterns = []
            for pattern in raw_patterns:
                weight = 7
                regex = None
                if isinstance(pattern, dict):
                    regex = pattern.get('regex') or pattern.get('pattern') or pattern.get('keyword') or pattern.get('value') or pattern.get('word')
                    if regex is None and isinstance(pattern.get('words'), list):
                        regex = "|".join(str(w) for w in pattern.get('words') if str(w))
                    weight = int(pattern.get('weight', weight)) if str(pattern.get('weight', '')).isdigit() else weight
                else:
                    regex = str(pattern)
                regex = regex.split('\\;')[0] if regex else regex
                regex = regex.replace('\\/', '/') if regex else regex
                if regex and len(regex) >= 3:
                    patterns.append((regex, max(1, min(weight, 10))))
            if patterns:
                parsed.append((product, patterns))
        return parsed

    def get_session(self):
        session = getattr(self.thread_local, 'session', None)
        if session is None:
            session = requests.Session()
            session.headers.update({'User-Agent': DEFAULT_UA})
            self.thread_local.session = session
        return session

    def get_shodan_key(self):
        if getattr(self.args, 'no_shodan', False):
            return ""
        return getattr(self.args, 'shodan_key', None) or os.environ.get('SHODAN_API_KEY') or ""

    def normalize_port(self, port):
        port = str(port or "").strip()
        if not port.isdigit():
            return ""
        number = int(port)
        return port if 1 <= number <= 65535 else ""

    def sort_ports(self, ports):
        return sorted((p for p in (self.normalize_port(port) for port in ports) if p), key=lambda p: int(p))

    def sort_ip_addresses(self, ips):
        valid_ips = []
        for ip in ips:
            try:
                valid_ips.append(ipaddress.ip_address(str(ip or "").strip()))
            except ValueError:
                continue
        return [str(ip) for ip in sorted(set(valid_ips), key=lambda x: (x.version, int(x)))]

    def get_shodan_ports(self, ip):
        key = self.get_shodan_key()
        if not key or not ip or ip in ("Unknown", "Skipped", "N/A"):
            return set()

        with self.lock:
            if ip in self.shodan_cache:
                return set(self.shodan_cache[ip])

        try:
            url = f"https://api.shodan.io/shodan/host/{ip}"
            r = self.get_session().get(url, params={"key": key, "minify": "true"}, timeout=12)
            if r.status_code == 404:
                ports = set()
            else:
                r.raise_for_status()
                data = r.json()
                ports = {self.normalize_port(p) for p in data.get('ports', [])}
                ports.update(self.normalize_port(item.get('port')) for item in data.get('data', []))
                ports.discard("")
            with self.lock:
                self.shodan_cache[ip] = ports
            return ports
        except Exception as e:
            if getattr(self.args, 'verbose', False):
                self.log(f"[!] Shodan lookup failed for {ip}: {str(e)[:100]}")
            with self.lock:
                self.shodan_cache[ip] = set()
            return set()

    def enrich_ports_from_shodan(self):
        if self.shodan_enriched:
            return
        self.shodan_enriched = True
        if not self.get_shodan_key():
            return
        ips = self.sort_ip_addresses({item.get('ip') for item in self.results})
        ips = [ip for ip in ips if ip not in ("Unknown", "Skipped", "N/A")]
        if not ips:
            return

        self.log(f"[*] Querying Shodan ports for {len(ips)} IP(s)...")
        for ip in ips:
            ports = self.get_shodan_ports(ip)
            if ports:
                with self.lock:
                    self.ip_ports[ip].update(ports)

    def get_driver(self):
        options = Options()
        options.page_load_strategy = 'eager' if getattr(self.args, 'fast', False) else 'normal'
        os.environ.pop('DISPLAY', None)
        os.environ.pop('WAYLAND_DISPLAY', None)
        os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
        os.environ.setdefault('GDK_BACKEND', 'headless')
        os.environ.setdefault('NO_AT_BRIDGE', '1')
        options.add_argument('--headless=new')
        options.add_argument('--ozone-platform=headless')
        options.add_argument('--disable-features=UseOzonePlatform')
        options.add_argument('--no-sandbox')
        options.add_argument('--disable-dev-shm-usage') 
        options.add_argument('--disable-gpu')
        options.add_argument('--disable-x11')            
        options.add_argument('--no-xshm')
        options.add_argument('--ignore-certificate-errors')
        options.add_argument('--window-size=1280,720')
        options.add_argument('--disable-software-rasterizer')
        options.add_argument('--no-zygote')
        options.add_argument(f'--user-agent={DEFAULT_UA}')
        options.add_argument('--disable-blink-features=AutomationControlled')
        options.add_argument('--log-level=3')
        options.add_argument('--js-flags="--max-old-space-size=512"')
        options.add_experimental_option("excludeSwitches", ["enable-automation", "enable-logging"])
        options.add_experimental_option('useAutomationExtension', False)
        if self.args.proxy:
            options.add_argument(f'--proxy-server={self.args.proxy}')
        service = Service(CHROME_DRIVER_PATH, log_output=os.devnull)
        driver = webdriver.Chrome(service=service, options=options)
        driver.execute_cdp_cmd("Page.addScriptToEvaluateOnNewDocument", {
            "source": "Object.defineProperty(navigator, 'webdriver', {get: () => undefined})"
        })
        self.configure_driver_runtime(driver)
        driver.set_page_load_timeout(self.args.timeout)
        return driver

    def configure_driver_runtime(self, driver):
        try:
            driver.execute_cdp_cmd("Network.enable", {})
            blocked = [
                "*.mp4", "*.webm", "*.avi", "*.mov", "*.m3u8",
                "*google-analytics.com*", "*googletagmanager.com*", "*doubleclick.net*",
                "*facebook.net*", "*hotjar.com*", "*clarity.ms*"
            ]
            if getattr(self.args, 'fast', False):
                blocked.extend(["*.woff", "*.woff2", "*.ttf", "*.otf"])
            driver.execute_cdp_cmd("Network.setBlockedURLs", {"urls": blocked})
        except:
            pass

    def wait_for_page_ready(self, driver):
        deadline = time.time() + max(1, self.args.timeout)
        while time.time() < deadline:
            try:
                state = driver.execute_script("return document.readyState")
                if state in ("interactive", "complete"):
                    break
            except:
                break
            time.sleep(0.1)
        time.sleep(max(0, self.args.render_wait))

    def candidate_urls(self, url):
        if url.startswith(('http://', 'https://')):
            return [url]
        return [f'http://{url}', f'https://{url}']

    def navigate(self, driver, url):
        last_error = None
        for target_url in self.candidate_urls(url):
            try:
                driver.get(target_url)
                return target_url, None
            except TimeoutException as e:
                # Chrome may have rendered enough content even when page load times out.
                try:
                    driver.execute_script("window.stop();")
                except:
                    pass
                return target_url, f"timeout: {str(e).splitlines()[0][:120]}"
            except WebDriverException as e:
                last_error = str(e).splitlines()[0][:160]
                continue
            except Exception as e:
                last_error = str(e).splitlines()[0][:160]
                continue
        return None, last_error or "navigation failed"

    def get_geo_info(self, hostname):
        if getattr(self.args, 'no_geo', False) or getattr(self.args, 'fast', False):
            return {"ip": "Skipped", "a_block": "N/A", "b_block": "N/A", "c_block": "N/A", "asn": "N/A", "org": "N/A", "cdn": "Skipped"}
        hostname_key = str(hostname or "").strip().lower()
        with self.lock:
            cached = HOST_GEO_CACHE.get(hostname_key)
            if cached:
                return cached
        try:
            resolved_ips = []
            for family, _, _, _, sockaddr in socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM):
                if family in (socket.AF_INET, socket.AF_INET6):
                    resolved_ips.append(sockaddr[0])
            if not resolved_ips:
                raise RuntimeError("no resolved addresses")
            ip_obj = sorted({ipaddress.ip_address(ip) for ip in resolved_ips}, key=lambda x: (x.version, int(x)))[0]
            ip = str(ip_obj)
            with self.lock:
                cached = GEO_CACHE.get(ip)
                if cached:
                    HOST_GEO_CACHE[hostname_key] = cached
                    return cached
            if ip_obj.version == 4:
                parts = ip.split('.')
                a_block = f"{parts[0]}.0.0.0/8"
                b_block = f"{parts[0]}.{parts[1]}.0.0/16"
                c_block = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
            else:
                a_block = str(ipaddress.ip_network(f"{ip}/16", strict=False))
                b_block = str(ipaddress.ip_network(f"{ip}/32", strict=False))
                c_block = str(ipaddress.ip_network(f"{ip}/48", strict=False))
            info = {
                "ip": ip,
                "a_block": a_block,
                "b_block": b_block,
                "c_block": c_block,
                "asn": "N/A", "org": "N/A", "cdn": "No"
            }
            try:
                res = self.get_session().get(f"http://ip-api.com/json/{ip}?fields=status,as,org,proxy", timeout=5).json()
                if res.get("status") == "success":
                    info["asn"] = res.get("as", "N/A")
                    info["org"] = res.get("org", "N/A")
                    info["cdn"] = "Yes" if res.get("proxy") else "No"
            except: pass
            with self.lock:
                GEO_CACHE[ip] = info
                HOST_GEO_CACHE[hostname_key] = info
            return info
        except:
            info = {"ip": "Unknown", "a_block": "N/A", "b_block": "N/A", "c_block": "N/A", "asn": "N/A", "org": "N/A", "cdn": "Unknown"}
            with self.lock:
                HOST_GEO_CACHE[hostname_key] = info
            return info

    def get_icon_features(self, html_content, base_url):
        """Fetch favicon and build exact plus perceptual hashes."""
        features = {"md5": "no-icon", "phash": None, "dhash": None, "url": "", "data": ""}
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            icon_urls = []
            for icon_link in soup.find_all("link", rel=lambda x: x and 'icon' in x.lower()):
                if icon_link.get('href'):
                    icon_urls.append(urljoin(base_url, icon_link['href']))
            icon_urls.append(urljoin(base_url, '/favicon.ico'))

            seen = set()
            for icon_url in icon_urls:
                if icon_url in seen:
                    continue
                seen.add(icon_url)
                try:
                    r = self.get_session().get(icon_url, timeout=5, verify=False)
                    content_type = r.headers.get('Content-Type', '').lower()
                    if r.status_code != 200 or not r.content or ('html' in content_type and len(r.content) > 512):
                        continue
                    features["md5"] = hashlib.md5(r.content).hexdigest()
                    features["url"] = icon_url
                    try:
                        with Image.open(io.BytesIO(r.content)) as icon_img:
                            icon_img = icon_img.convert('RGBA').resize((64, 64), Image.LANCZOS)
                            icon_rgb = icon_img.convert('RGB')
                            features["phash"] = imagehash.phash(icon_rgb)
                            features["dhash"] = imagehash.dhash(icon_rgb)
                            icon_name = f"icon_{features['md5'][:16]}.png"
                            icon_path = os.path.join(self.assets_path, icon_name)
                            if not os.path.exists(icon_path):
                                icon_img.save(icon_path, "PNG", optimize=True)
                            features["data"] = f"{self.assets_dirname}/{icon_name}"
                    except:
                        pass
                    return features
                except:
                    continue
        except: pass
        return features

    def get_icon_hash(self, html_content, base_url):
        return self.get_icon_features(html_content, base_url)["md5"]

    def normalize_text(self, text, max_len=1600):
        text = (text or "").lower()
        text = NORMALIZE_URL_RE.sub(" ", text)
        text = NORMALIZE_HEX_RE.sub(" ", text)
        text = NORMALIZE_DIGITS_RE.sub("#", text)
        text = NORMALIZE_SPACE_RE.sub(" ", text).strip()
        return text[:max_len]

    def get_text_hash(self, visible_text):
        normalized = self.normalize_text(visible_text)
        if not normalized:
            return "no-text"
        return hashlib.md5(normalized.encode("utf-8")).hexdigest()

    def get_dom_hash(self, html_content):
        """Build a stable page-template hash by ignoring volatile content and attributes."""
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            for tag in soup(["script", "style", "noscript", "svg", "meta"]):
                tag.decompose()

            structural_tags = []
            useful_tags = {
                "html", "body", "header", "nav", "main", "section", "article", "aside", "footer",
                "div", "form", "fieldset", "label", "input", "select", "textarea", "button",
                "table", "thead", "tbody", "tr", "th", "td", "ul", "ol", "li", "a", "img",
                "h1", "h2", "h3", "p"
            }
            for el in soup.find_all():
                if el.name not in useful_tags:
                    continue
                attrs = []
                if el.name == "input" and el.get("type"):
                    attrs.append(f"type={el.get('type')}")
                if el.name == "form" and el.get("method"):
                    attrs.append(f"method={el.get('method').lower()}")
                structural_tags.append(el.name + ("[" + ",".join(attrs) + "]" if attrs else ""))

            signature = "|".join(structural_tags)
            if not signature:
                return "no-dom"
            return hashlib.md5(signature.encode("utf-8")).hexdigest()
        except:
            return "no-dom"

    def get_path_signature(self, url):
        try:
            path = urlparse(url).path.lower().strip('/')
            if not path:
                return "/"
            parts = []
            for part in path.split('/'):
                part = NORMALIZE_DIGITS_RE.sub("#", part)
                part = PATH_HEX_RE.sub("*", part)
                parts.append(part)
            return "/" + "/".join(parts[:4])
        except:
            return "/"

    def get_visual_hashes(self, img):
        normalized = img.convert('RGB').resize((800, 450), Image.LANCZOS)
        return {
            "ahash": imagehash.average_hash(normalized),
            "phash": imagehash.phash(normalized),
            "dhash": imagehash.dhash(normalized),
        }, normalized

    def safe_pattern_match(self, pattern, text):
        if not pattern:
            return False
        pattern = str(pattern)
        try:
            return re.search(pattern, text, re.I) is not None
        except re.error:
            # External fingerprint libraries often contain pseudo-regex or raw
            # product strings. Treat invalid regex as a literal substring instead
            # of failing the whole scan task.
            literal = LITERAL_UNESCAPE_RE.sub(r"\1", pattern).lower()
            literal = literal.replace(".*", " ").replace("\\", "")
            literal = LITERAL_STRIP_RE.sub("", literal).strip()
            return bool(literal and literal in text.lower())

    def detect_device_product(self, title, visible_text, html_content, techs):
        tech_text = " ".join(techs or []).lower()
        page_text = self.normalize_text(f"{title} {visible_text}", max_len=5000)
        html_text = (html_content or "").lower()[:8000]
        combined = f"{tech_text} {page_text} {html_text}"

        if any(cms in combined for cms in CMS_EXCLUSIONS):
            return "", 0, "CMS excluded"

        best_product = ""
        best_score = 0
        best_hits = []
        for product, patterns in self.compiled_device_rules:
            score = 0
            hits = []
            for pattern, weight, compiled_pattern, literal in patterns:
                if (compiled_pattern.search(combined) if compiled_pattern else literal in combined):
                    score += weight
                    hits.append(pattern)
            if score > best_score:
                best_product = product
                best_score = score
                best_hits = hits

        # Built-in device fingerprints are curated. External online libraries are
        # broad and noisy, so require stronger evidence to reduce false positives.
        required_score = 12 if best_product in self.external_products else 7
        required_hits = 2 if best_product in self.external_products else 1
        if best_score >= required_score and len(best_hits) >= required_hits:
            return best_product, best_score, ",".join(best_hits[:3])
        return "", best_score, "weak evidence"

    def standalone_task_wrapper(self, url):
        if not self.is_running: return
        driver = None
        try:
            driver = self.get_driver()
            self.execute_task(driver, url)
        except Exception as e:
            self.log(f"[-] Fatal Error on {url}: {str(e)[:60]}")
        finally:
            if driver:
                try: driver.quit()
                except: pass
            gc.collect()

    def worker_task(self, urls):
        driver = None
        try:
            driver = self.get_driver()
            while self.is_running:
                try:
                    url = urls.get_nowait() if hasattr(urls, 'get_nowait') else urls.pop(0)
                except (queue.Empty, IndexError):
                    break
                if not self.is_running:
                    break
                try:
                    self.execute_task(driver, url)
                except Exception as e:
                    self.log(f"[-] Fatal Error on {url}: {str(e)[:60]}")
                    try:
                        if driver:
                            driver.quit()
                    except:
                        pass
                    try:
                        driver = self.get_driver()
                    except Exception as restart_error:
                        self.log(f"[-] Browser restart failed: {str(restart_error)[:60]}")
                        break
                finally:
                    if self.pbar:
                        with self.lock:
                            self.pbar.update(1)
        finally:
            if driver:
                try: driver.quit()
                except: pass
            session = getattr(self.thread_local, 'session', None)
            if session:
                try: session.close()
                except: pass
            gc.collect()

    def execute_task(self, driver, url):
        input_url = url.strip()
        parsed_url = urlparse(input_url if input_url.startswith(('http://', 'https://')) else f'http://{input_url}')
        hostname = parsed_url.hostname or "unknown"
        port = parsed_url.port or (443 if parsed_url.scheme == 'https' else 80)
        last_error = "unknown"

        for attempt in range(self.args.retries):
            try:
                status_code, final_url, media_type = "N/A", input_url, "N/A"
                if not getattr(self.args, 'no_http_check', False) and not getattr(self.args, 'fast', False):
                    try:
                        check_url = input_url if input_url.startswith(('http://', 'https://')) else f'http://{input_url}'
                        r = self.get_session().get(check_url, timeout=10, verify=False, allow_redirects=True,
                                             proxies={'http':self.args.proxy, 'https':self.args.proxy} if self.args.proxy else None)
                        status_code, final_url = r.status_code, r.url
                        media_type = (r.headers.get('Content-Type') or "N/A").split(';', 1)[0].strip().lower() or "N/A"
                    except: pass

                navigated_url, nav_error = self.navigate(driver, input_url)
                if not navigated_url:
                    raise RuntimeError(nav_error)
                if nav_error and getattr(self.args, 'verbose', False):
                    self.log(f"[!] Navigation warning {navigated_url}: {nav_error}")
                self.wait_for_page_ready(driver)
                try:
                    final_url = driver.current_url or final_url
                except:
                    pass
                if media_type == "N/A":
                    try:
                        media_type = (driver.execute_script("return document.contentType || ''; ") or "N/A").strip().lower() or "N/A"
                    except:
                        media_type = "N/A"
                
                # 新增特征提取
                page_source = driver.page_source
                icon_features = self.get_icon_features(page_source, navigated_url)
                icon_hash = icon_features["md5"]
                dom_hash = self.get_dom_hash(page_source)
                title = (driver.title or "No Title").strip()
                title_norm = self.normalize_text(title, max_len=200)
                try:
                    visible_text = driver.execute_script("return document.body ? document.body.innerText : '';") or ""
                except:
                    visible_text = ""
                text_hash = self.get_text_hash(visible_text)
                try:
                    h1_text = driver.execute_script("let h=document.querySelector('h1'); return h ? h.innerText : ''; ") or ""
                except:
                    h1_text = ""
                path_sig = self.get_path_signature(final_url or url)
                
                geo = self.get_geo_info(hostname)
                with self.lock:
                    self.ip_ports[geo['ip']].add(str(port))
                
                img_name = f"{base64.urlsafe_b64encode(input_url.encode()).decode()[:12]}_{int(time.time()*1000)}.jpg"
                screenshot_path = os.path.join(self.assets_path, img_name)

                screenshot_png = driver.get_screenshot_as_png()
                with Image.open(io.BytesIO(screenshot_png)) as img:
                    visual_hashes, _ = self.get_visual_hashes(img)
                    w, h = img.size
                    new_w = 800
                    new_h = int(h * (new_w / w))
                    img = img.resize((new_w, new_h), Image.LANCZOS)
                    img.convert('RGB').save(screenshot_path, "JPEG", quality=50, optimize=True)
                
                if getattr(self.args, 'no_tech', False) or getattr(self.args, 'fast', False):
                    techs = []
                else:
                    try: techs = list(WAPPALYZER_INST.analyze(WebPage.new_from_url(final_url or navigated_url)))
                    except: techs = []
                device_product, device_score, device_evidence = self.detect_device_product(title, visible_text, page_source, techs)
                
                final_data = {
                    "url": navigated_url, "final_url": final_url, "status": status_code,
                    "media_type": media_type,
                    "title": title, "title_norm": title_norm, "h1": self.normalize_text(h1_text, max_len=200), "hostname": hostname,
                    "ip": geo['ip'], "port": port, 
                    "a_block": geo['a_block'], "b_block": geo['b_block'], "c_block": geo['c_block'],
                    "asn": geo['asn'], "org": geo['org'], "cdn": geo['cdn'],
                    "data": f"{self.assets_dirname}/{img_name}", "tech": techs,
                    "img_hash": visual_hashes["phash"], "ahash": visual_hashes["ahash"],
                    "phash": visual_hashes["phash"], "dhash": visual_hashes["dhash"],
                    "icon_hash": icon_hash, "icon_phash": icon_features["phash"],
                    "icon_dhash": icon_features["dhash"], "icon_url": icon_features["url"],
                    "icon_data": icon_features["data"],
                    "dom_hash": dom_hash, "text_hash": text_hash,
                    "path_sig": path_sig, "device_product": device_product,
                    "device_score": device_score, "device_evidence": device_evidence,
                    "group_score": 100, "group_reason": "seed"
                }
                with self.lock: self.results.append(final_data)
                break 
            except Exception as e:
                last_error = str(e).splitlines()[0][:180]
                if attempt == self.args.retries - 1:
                    self.log(f"[-] Failed {input_url} after {attempt+1} retries: {last_error}")
                else:
                    try:
                        driver.execute_script("window.stop();")
                    except:
                        pass
                    time.sleep(0.5)

    def generate_html(self):
        if not self.results: 
            self.log("[!] No results to generate report.")
            return
        self.enrich_ports_from_shodan()
        self.log("[*] Smart Grouping assets...")
        groups = self.cluster_results()
        
        c_blocks = sorted(list(set(item['c_block'] for item in self.results if item['c_block'] != "N/A")))
        asns = sorted(list(set(item['asn'] for item in self.results if item['asn'] != "N/A")))
        
        summary_html = f"""
        <div class="stats-container">
            <div class="stat-card"><b>Total Assets</b><span>{len(self.results)}</span></div>
            <div class="stat-card"><b>Groups</b><span>{len(groups)}</span></div>
            <div class="stat-card"><b>C-Blocks</b><div class="stat-tags">{" ".join([f'<span class="s-tag">{self.esc(b)}</span>' for b in c_blocks[:20]])}</div></div>
            <div class="stat-card"><b>ASNs</b><div class="stat-tags">{" ".join([f'<span class="s-tag">{self.esc(a)}</span>' for a in asns[:10]])}</div></div>
        </div>"""
        
        html_content = self.get_template().replace("{content}", summary_html + self.build_sections(groups))
        with open(self.args.report, "w", encoding="utf-8") as f:
            f.write(html_content)
        self.log(f"\n[+] Report saved: {os.path.abspath(self.args.report)}")

    def esc(self, value):
        return html.escape(str(value or ""), quote=True)

    def visual_distance(self, item, rep):
        try:
            return (
                (item['phash'] - rep['phash']) * 0.5 +
                (item['dhash'] - rep['dhash']) * 0.3 +
                (item['ahash'] - rep['ahash']) * 0.2
            )
        except:
            return 999

    def icon_distance(self, item, rep):
        try:
            if item.get('icon_phash') is None or rep.get('icon_phash') is None:
                return 999
            return (
                (item['icon_phash'] - rep['icon_phash']) * 0.65 +
                (item['icon_dhash'] - rep['icon_dhash']) * 0.35
            )
        except:
            return 999

    def tech_overlap(self, item, rep):
        item_tech = set(t.lower() for t in item.get("tech", []))
        rep_tech = set(t.lower() for t in rep.get("tech", []))
        if not item_tech or not rep_tech:
            return 0
        return len(item_tech & rep_tech) / len(item_tech | rep_tech)

    def score_similarity(self, item, rep):
        score = 0
        reasons = []
        sim_val = max(1, self.args.similarity)

        if item.get('device_product') and rep.get('device_product') and item.get('device_product') != rep.get('device_product'):
            score -= 35
            reasons.append("ProductMismatch")

        if item.get('device_product') and item.get('device_product') == rep.get('device_product'):
            score += 40
            reasons.append(f"Product:{item.get('device_product')}")

        if item.get('dom_hash') != "no-dom" and item.get('dom_hash') == rep.get('dom_hash'):
            score += 35
            reasons.append("DOM")

        if item.get('text_hash') != "no-text" and item.get('text_hash') == rep.get('text_hash'):
            score += 20
            reasons.append("Text")

        vdist = self.visual_distance(item, rep)
        if vdist <= sim_val:
            score += 35
            reasons.append(f"Visual:{vdist:.1f}")
        elif vdist <= sim_val * 2:
            score += 24
            reasons.append(f"Visual:{vdist:.1f}")
        elif vdist <= sim_val * 3:
            score += 12
            reasons.append(f"Visual:{vdist:.1f}")

        if item.get('title_norm') and item.get('title_norm') == rep.get('title_norm') and item.get('title') != "No Title":
            score += 12
            reasons.append("Title")

        if item.get('h1') and item.get('h1') == rep.get('h1'):
            score += 8
            reasons.append("H1")

        if item.get('icon_hash') != "no-icon" and item.get('icon_hash') == rep.get('icon_hash'):
            score += 18
            reasons.append("Icon")
        else:
            idist = self.icon_distance(item, rep)
            if idist <= 4:
                score += 16
                reasons.append(f"IconSimilar:{idist:.1f}")
            elif idist <= 8:
                score += 8
                reasons.append(f"IconSimilar:{idist:.1f}")

        tech_sim = self.tech_overlap(item, rep)
        if tech_sim >= 0.7:
            score += 8
            reasons.append("Tech")
        elif tech_sim >= 0.4:
            score += 4
            reasons.append("Tech")

        if item.get('path_sig') == rep.get('path_sig') and item.get('path_sig') != "/":
            score += 5
            reasons.append("Path")

        return score, ", ".join(reasons) if reasons else "low-confidence"

    def hash_segments(self, hash_obj, prefix):
        try:
            hash_hex = str(hash_obj)
            return [(prefix, i, hash_hex[i:i+2]) for i in range(0, len(hash_hex), 2)]
        except:
            return []

    def index_keys(self, item):
        keys = []
        if item.get('dom_hash') and item.get('dom_hash') != "no-dom":
            keys.append(('dom', item['dom_hash']))
        if item.get('text_hash') and item.get('text_hash') != "no-text":
            keys.append(('text', item['text_hash']))
        if item.get('title_norm') and item.get('title') != "No Title":
            keys.append(('title', item['title_norm']))
        if item.get('h1'):
            keys.append(('h1', item['h1']))
        if item.get('icon_hash') and item.get('icon_hash') != "no-icon":
            keys.append(('icon', item['icon_hash']))
        if item.get('path_sig') and item.get('path_sig') != "/":
            keys.append(('path', item['path_sig']))
        if item.get('device_product'):
            keys.append(('product', item['device_product']))
        keys.extend(self.hash_segments(item.get('phash'), 'phash'))
        keys.extend(self.hash_segments(item.get('dhash'), 'dhash'))
        keys.extend(self.hash_segments(item.get('icon_phash'), 'icon_phash'))
        keys.extend(self.hash_segments(item.get('icon_dhash'), 'icon_dhash'))
        return keys

    def add_to_group_index(self, group_index, item, group_id):
        for key in self.index_keys(item):
            group_index[key].add(group_id)

    def candidate_group_ids(self, group_index, item, group_count):
        candidate_ids = set()
        for key in self.index_keys(item):
            candidate_ids.update(group_index.get(key, ()))

        # For the first few groups, a full scan avoids early fragmentation. Once the
        # report grows large, indexed lookup keeps grouping near-linear.
        if group_count <= 200:
            candidate_ids.update(range(group_count))
        return candidate_ids

    def maybe_add_group_representative(self, group, item):
        reps = group['reps']
        if len(reps) >= MAX_GROUP_REPRESENTATIVES:
            return
        sim_val = max(1, self.args.similarity)
        if all(self.visual_distance(item, rep) > sim_val * 2 for rep in reps):
            reps.append(item)

    def group_similarity(self, group_a, group_b):
        best_score = 0
        best_reason = "low-confidence"
        for rep_a in group_a['reps']:
            for rep_b in group_b['reps']:
                score, reason = self.score_similarity(rep_a, rep_b)
                if score > best_score:
                    best_score = score
                    best_reason = reason
        return best_score, best_reason

    def merge_similar_groups(self, groups):
        if len(groups) < 2:
            return groups

        parent = list(range(len(groups)))

        def find(x):
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        def union(a, b):
            root_a, root_b = find(a), find(b)
            if root_a != root_b:
                parent[root_b] = root_a

        group_index = defaultdict(set)
        for group_id, group in enumerate(groups):
            for rep in group['reps']:
                self.add_to_group_index(group_index, rep, group_id)

        merge_threshold = GROUP_SCORE_THRESHOLD + 8
        for group_id, group in enumerate(groups):
            candidate_ids = set()
            for rep in group['reps']:
                candidate_ids.update(self.candidate_group_ids(group_index, rep, len(groups)))
            for candidate_id in candidate_ids:
                if candidate_id <= group_id:
                    continue
                score, reason = self.group_similarity(group, groups[candidate_id])
                if score >= merge_threshold:
                    for item in groups[candidate_id]['items']:
                        item['group_score'] = score
                        item['group_reason'] = f"Merged: {reason}"
                    union(group_id, candidate_id)

        merged = {}
        for group_id, group in enumerate(groups):
            root = find(group_id)
            if root not in merged:
                merged[root] = {'items': [], 'reps': [], 'img_hash': group['img_hash'], 'icon_hash': group['icon_hash'], 'dom_hash': group['dom_hash']}
            merged[root]['items'].extend(group['items'])
            for rep in group['reps']:
                if len(merged[root]['reps']) < MAX_GROUP_REPRESENTATIVES:
                    merged[root]['reps'].append(rep)
        return list(merged.values())

    def group_device_product(self, group):
        counts = defaultdict(int)
        for item in group['items']:
            product = item.get('device_product')
            if product:
                counts[product] += 1
        if not counts:
            return ""
        return max(counts.items(), key=lambda x: x[1])[0]

    def group_priority(self, group):
        product = self.group_device_product(group)
        if not product:
            return 100000
        priority = self.product_priority.get(product, self.priority_from_product_name(product))
        return priority if priority < 100000 else 100000

    def cluster_results(self):
        """核心：基于 DOM/Text/Visual/Title/Icon/Tech 的加权聚合规则"""
        groups = []
        group_index = defaultdict(set)
        threshold = GROUP_SCORE_THRESHOLD
        for item in self.results:
            best_group = None
            best_score = 0
            best_reason = "seed"
            best_group_id = None

            for group_id in self.candidate_group_ids(group_index, item, len(groups)):
                group = groups[group_id]
                for rep in group['reps']:
                    score, reason = self.score_similarity(item, rep)
                    if score > best_score:
                        best_group = group
                        best_score = score
                        best_reason = reason
                        best_group_id = group_id

            if best_group and best_score >= threshold:
                item['group_score'] = best_score
                item['group_reason'] = best_reason
                best_group['items'].append(item)
                self.maybe_add_group_representative(best_group, item)
                self.add_to_group_index(group_index, item, best_group_id)
            else:
                item['group_score'] = 100
                item['group_reason'] = "seed"
                group_id = len(groups)
                groups.append({'items': [item], 'reps': [item], 'img_hash': item['img_hash'], 'icon_hash': item['icon_hash'], 'dom_hash': item['dom_hash']})
                self.add_to_group_index(group_index, item, group_id)
        return self.merge_similar_groups(groups)

    def build_sections(self, groups):
        sections = []
        nav_items = []
        groups.sort(key=lambda x: (self.group_priority(x), -len(x['items'])))
        for i, group in enumerate(groups):
            rep = group['items'][0]
            # 提取该组的核心特征作为标题
            group_product = self.group_device_product(group)
            tech_summary = ", ".join(rep['tech'][:2]) if rep['tech'] else "General"
            product_label = f"Hardware Product: {group_product} | " if group_product else ""
            feature_label = self.esc(f"{product_label}Title: {rep['title']} | Tech: {tech_summary} | DOM: {rep.get('dom_hash', 'N/A')[:8]}")
            group_id = f"group-{i+1}"
            group_name = self.esc(f"Group {i+1} - {len(group['items'])} Similar Assets")
            group_nav_title = self.esc(f"{rep['title']} | {tech_summary}")
            nav_items.append(f'''
                <button type="button" class="side-nav-item" data-target="{group_id}" title="{group_nav_title}" onclick="jumpToGroup('{group_id}')">
                    <span>{group_name}</span>
                    <small>{self.esc(tech_summary)}</small>
                </button>''')
            
            cards = []
            for item in group['items']:
                st = str(item['status'])
                if st.startswith('2'):
                    st_cls = "st-2xx"
                elif st.startswith('3'):
                    st_cls = "st-3xx"
                elif st.startswith('4'):
                    st_cls = "st-4xx"
                elif st.startswith('5'):
                    st_cls = "st-5xx"
                else:
                    st_cls = "st-other"
                ports_list = self.esc(", ".join(self.sort_ports(self.ip_ports[item['ip']])))
                tech_str = self.esc("|".join(item["tech"]).lower())
                safe_title = self.esc(item["title"])
                safe_url = self.esc(item["url"])
                safe_final_url = self.esc(item["final_url"])
                safe_data = self.esc(item["data"])
                safe_ip = self.esc(item["ip"])
                safe_host = self.esc(item["hostname"])
                safe_port = self.esc(item["port"])
                safe_media_type = self.esc(item.get("media_type", "N/A"))
                safe_asn = self.esc(item["asn"])
                safe_group = self.esc(f"{item.get('group_score', 0)} / {item.get('group_reason', 'N/A')}")
                product_text = item.get('device_product') or "N/A"
                if item.get('device_product'):
                    product_text = f"Hardware: {product_text} ({item.get('device_score', 0)})"
                safe_product = self.esc(product_text)
                safe_icon = self.esc(item["icon_hash"][:8] if item["icon_hash"]!="no-icon" else "N/A")
                safe_icon_data = self.esc(item.get("icon_data", ""))
                title_icon = f'<img class="title-favicon" src="{safe_icon_data}" loading="lazy" alt="icon">' if safe_icon_data else '<span class="title-favicon default-favicon"></span>'
                safe_tags = "".join(f'<span class="tag">{self.esc(t)}</span>' for t in item["tech"])
                redirect_box = f'<div class="redirect-info">↪ {safe_final_url}</div>' if item['url'] != item['final_url'] else ""
                cards.append(f'''
                <div class="card" data-ip="{safe_ip}" data-domain="{safe_host}" data-tech="{tech_str}" data-media="{safe_media_type}" data-status="{self.esc(item['status'])}" data-port="{safe_port}">
                    <div class="card-title" title="{safe_title}">{title_icon}<span>{safe_title}</span></div>
                    <div class="img-wrapper" onclick="zoom('{safe_data}')"><img src="{safe_data}" loading="lazy" alt="screenshot"></div>
                    <div class="card-info">
                        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
                            <span class="status-badge {st_cls}">HTTP {self.esc(item['status'])}</span>
                            <a href="{safe_url}" target="_blank" class="url-link">Open Link</a>
                        </div>
                        <div class="url-text">{safe_url}</div>{redirect_box}
                        <div class="detail-grid">
                            <p><b>IP</b><span>{safe_ip}</span></p>
                            <p><b>Port</b><span>{safe_port} <small>(All: {ports_list})</small></span></p>
                            <p><b>Media Type</b><span>{safe_media_type}</span></p>
                            <p><b>ASN</b><span>{safe_asn}</span></p>
                            <p><b>Product</b><span>{safe_product}</span></p>
                            <p><b>Group</b><span>{safe_group}</span></p>
                            <p><b>Icon</b><span style="font-family:monospace; font-size:9px;">{safe_icon}</span></p>
                        </div>
                        <div class="tags">{safe_tags}</div>
                    </div>
                </div>''')

            sections.append(f'''
            <details open class="group-section" id="{group_id}">
                <summary>
                    <div style="display:flex; flex-direction:column; gap:4px;">
                        <span class="g-title">Group {i+1} - {len(group["items"])} Similar Assets</span>
                        <span style="font-size:11px; color:#94a3b8; font-weight:normal;">Feature: {feature_label}</span>
                    </div>
                    <span class="g-indicator">Current Group</span>
                </summary>
                <div class="grid">{"".join(cards)}</div>
            </details>''')
        return f'''
        <aside id="groupSidebar" class="group-sidebar">
            <div class="sidebar-panel">
                <div class="sidebar-head">
                    <b>Groups</b>
                    <span>{len(groups)}</span>
                </div>
                <div class="side-nav-list">{"".join(nav_items)}</div>
            </div>
        </aside>
        <div id="groupsRoot">{"".join(sections)}</div>'''

    def get_template(self):
        # ... (保持原有的 get_template 样式不变，确保UI一致性)
        return f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><style>
        :root {{ --primary: #2563eb; --primary-light: #dbeafe; --bg: #f8fafc; --text: #1e293b; --border: #e2e8f0; }}
        body {{ font-family: 'Inter', system-ui, -apple-system, sans-serif; background: var(--bg); color: var(--text); margin: 0; padding: 20px; line-height: 1.5; scroll-behavior: smooth; }}
        .controls {{ position: fixed; top: 0; left: 0; right: 0; background: rgba(255,255,255,0.9); backdrop-filter: blur(10px); z-index: 1000; padding: 10px 25px; display: flex; align-items: center; gap: 20px; border-bottom: 1px solid var(--border); box-shadow: 0 1px 2px rgba(0,0,0,0.05); }}
        .search-box {{ display: flex; flex-grow: 1; max-width: 500px; background: #fff; border: 1px solid var(--border); border-radius: 8px; overflow: hidden; }}
        .search-box select {{ border: none; padding: 8px 12px; background: #f1f5f9; font-size: 13px; border-right: 1px solid var(--border); outline: none; }}
        .search-box input {{ border: none; padding: 8px 15px; flex-grow: 1; outline: none; font-size: 14px; }}
        .scroll-fab {{ position: fixed; right: 30px; width: 45px; height: 45px; background: var(--primary); color: white; border: none; border-radius: 50%; cursor: pointer; display: none; align-items: center; justify-content: center; box-shadow: 0 4px 12px rgba(37,99,235,0.4); z-index: 1001; transition: all 0.3s; font-size: 20px; border: 1px solid rgba(255,255,255,0.2); }}
        .scroll-fab:hover {{ transform: translateY(-2px); box-shadow: 0 8px 18px rgba(37,99,235,0.45); }}
        #backToTop {{ bottom: 84px; }}
        #backToBottom {{ bottom: 30px; }}
        .sticky-group-bar {{ position: fixed; top: 60px; left: 50%; transform: translateX(-50%); z-index: 999; background: var(--primary); color: white; padding: 6px 20px; border-radius: 0 0 15px 15px; font-weight: 700; font-size: 13px; box-shadow: 0 4px 12px rgba(37,99,235,0.3); display: none; transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1); cursor: pointer; border: 1px solid rgba(255,255,255,0.2); border-top: none; }}
        .container {{ max-width: 1600px; margin: 80px auto 0; }}
        .stats-container {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 30px; }}
        .stat-card {{ background: white; padding: 15px; border-radius: 12px; border: 1px solid var(--border); box-shadow: 0 2px 4px rgba(0,0,0,0.02); }}
        .stat-card b {{ display: block; color: #64748b; font-size: 12px; text-transform: uppercase; margin-bottom: 5px; }}
        .stat-card span {{ font-size: 20px; font-weight: 800; color: var(--primary); }}
        .stat-tags {{ display: flex; flex-wrap: wrap; gap: 4px; margin-top: 5px; }}
        .s-tag {{ background: #eff6ff; color: #1e40af; padding: 2px 6px; border-radius: 4px; font-size: 11px; border: 1px solid #dbeafe; }}
        details {{ background: white; border-radius: 12px; margin-bottom: 30px; border: 1px solid var(--border); overflow: hidden; transition: box-shadow 0.3s; }}
        summary {{ padding: 15px 20px; cursor: pointer; font-weight: 700; background: #fff; list-style: none; display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid transparent; }}
        details[open] summary {{ border-bottom-color: var(--border); background: #fcfcfd; }}
        .g-indicator {{ font-size: 10px; background: var(--primary); color: white; padding: 2px 8px; border-radius: 10px; opacity: 0; transition: opacity 0.3s; }}
        details.active-group {{ border-color: var(--primary); }}
        details.active-group .g-indicator {{ opacity: 1; }}
        .controls button {{ border: 1px solid var(--border); background: #fff; color: #475569; border-radius: 8px; padding: 7px 10px; font-size: 12px; font-weight: 700; cursor: pointer; transition: all 0.2s; }}
        .controls button:hover {{ color: var(--primary); border-color: #bfdbfe; background: #eff6ff; }}
        summary::after {{ content: '→'; transition: transform 0.3s; color: #94a3b8; font-weight: bold; }}
        details[open] summary::after {{ transform: rotate(90deg); }}
        .grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(350px, 1fr)); gap: 20px; padding: 20px; background: #f1f5f9; }}
        .card {{ background: white; border: 1px solid var(--border); border-radius: 12px; overflow: hidden; display: flex; flex-direction: column; transition: all 0.3s; position: relative; }}
        .card:hover {{ transform: translateY(-5px); box-shadow: 0 10px 25px rgba(0,0,0,0.1); border-color: var(--primary); }}
        .card-title {{ padding: 12px 15px; font-size: 13px; font-weight: 700; background: #fff; border-bottom: 1px solid #f1f5f9; white-space: nowrap; overflow: hidden; color: var(--primary); display: flex; align-items: center; gap: 8px; }}
        .card-title span:last-child {{ min-width: 0; overflow: hidden; text-overflow: ellipsis; }}
        .title-favicon {{ width: 16px; height: 16px; flex: 0 0 16px; object-fit: contain; border-radius: 3px; }}
        .default-favicon {{ display: inline-block; box-sizing: border-box; border: 1px solid #cbd5e1; background: linear-gradient(135deg, #f8fafc 0 72%, #e2e8f0 72% 100%); position: relative; }}
        .default-favicon::after {{ content: ''; position: absolute; right: -1px; top: -1px; width: 6px; height: 6px; background: #e2e8f0; border-left: 1px solid #cbd5e1; border-bottom: 1px solid #cbd5e1; }}
        .img-wrapper {{ height: 180px; overflow: hidden; cursor: zoom-in; background: #cbd5e1; border-bottom: 1px solid var(--border); }}
        .img-wrapper img {{ width: 100%; height: 100%; object-fit: cover; object-position: top; }}
        .card-info {{ padding: 15px; flex-grow: 1; }}
        .status-badge {{ font-size: 11px; font-weight: 700; padding: 3px 8px; border-radius: 20px; }}
        .st-2xx {{ background: #dcfce7; color: #166534; }}
        .st-3xx {{ background: #fef9c3; color: #854d0e; }}
        .st-4xx {{ background: #fee2e2; color: #991b1b; }}
        .st-5xx {{ background: #ffe4e6; color: #9f1239; }}
        .st-other {{ background: #e2e8f0; color: #475569; }}
        .url-link {{ font-size: 12px; color: var(--primary); text-decoration: none; font-weight: 600; }}
        .url-text {{ font-family: monospace; font-size: 11px; color: #64748b; margin: 8px 0; word-break: break-all; }}
        .redirect-info {{ font-size: 10px; color: #f59e0b; background: #fffbeb; padding: 4px 8px; border-radius: 4px; margin-bottom: 10px; border: 1px solid #fef3c7; }}
        .detail-grid {{ display: grid; grid-template-columns: 1fr; gap: 5px; font-size: 12px; border-top: 1px solid #f1f5f9; padding-top: 10px; }}
        .detail-grid p {{ margin: 0; display: flex; justify-content: space-between; padding: 2px 0; }}
        .detail-grid b {{ color: #64748b; font-weight: 500; }}
        .tags {{ margin-top: 12px; display: flex; flex-wrap: wrap; gap: 4px; }}
        .tag {{ background: #f8fafc; color: #475569; padding: 2px 8px; border-radius: 4px; font-size: 10px; border: 1px solid var(--border); }}
        .group-sidebar {{ position: fixed; top: 88px; right: 18px; width: 245px; z-index: 998; transition: transform 0.25s ease, opacity 0.25s ease; }}
        .group-sidebar.collapsed {{ transform: translateX(calc(100% + 36px)); opacity: 0; pointer-events: none; }}
        .sidebar-toggle {{ position: fixed; top: 12px; right: 24px; z-index: 1002; border: 1px solid #bfdbfe; background: rgba(255,255,255,0.78); color: var(--primary); border-radius: 999px; padding: 8px 14px; font-weight: 800; cursor: pointer; box-shadow: 0 6px 18px rgba(15,23,42,0.08); backdrop-filter: blur(12px); transition: all 0.2s; }}
        .sidebar-toggle:hover {{ background: rgba(239,246,255,0.9); transform: translateY(-1px); }}
        .sidebar-panel {{ max-height: calc(100vh - 125px); overflow: hidden; display: flex; flex-direction: column; border: 1px solid rgba(191,219,254,0.82); border-radius: 14px; background: rgba(255,255,255,0.74); box-shadow: 0 16px 40px rgba(15,23,42,0.12); backdrop-filter: blur(16px); }}
        .sidebar-head {{ display: flex; justify-content: space-between; align-items: center; padding: 12px 14px; color: var(--primary); border-bottom: 1px solid rgba(226,232,240,0.85); }}
        .sidebar-head span {{ font-size: 12px; color: #64748b; background: #eff6ff; border: 1px solid #dbeafe; border-radius: 999px; padding: 2px 8px; }}
        .side-nav-list {{ overflow-y: auto; padding: 8px; }}
        .side-nav-item {{ width: 100%; border: 1px solid transparent; background: transparent; border-radius: 10px; padding: 8px 9px; text-align: left; cursor: pointer; color: #334155; display: flex; flex-direction: column; gap: 2px; transition: all 0.2s; }}
        .side-nav-item span {{ font-size: 12px; font-weight: 800; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
        .side-nav-item small {{ font-size: 10px; color: #94a3b8; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
        .side-nav-item:hover, .side-nav-item.active {{ background: #eff6ff; border-color: #bfdbfe; color: var(--primary); }}
        .report-footer {{ text-align: center; color: #64748b; font-size: 12px; padding: 24px 10px 8px; }}
        .report-footer a {{ color: var(--primary); font-weight: 700; text-decoration: none; }}
        .report-footer a:hover {{ text-decoration: underline; }}
        #lb {{ display: none; position: fixed; inset: 0; background: rgba(15,23,42,0.9); z-index: 2000; justify-content: center; align-items: center; cursor: zoom-out; }}
        #lb img {{ max-width: 95%; max-height: 95%; border-radius: 8px; }}
        @media (max-width: 900px) {{
            body {{ padding: 14px; }}
            .controls {{ padding: 8px 12px; gap: 8px; flex-wrap: wrap; }}
            .container {{ margin-top: 120px; }}
            .group-sidebar {{ top: 128px; right: 10px; width: 220px; }}
            .group-sidebar.collapsed {{ transform: translateX(calc(100% + 24px)); }}
            .grid {{ grid-template-columns: 1fr; }}
            summary {{ align-items: flex-start; gap: 8px; }}
            .sidebar-toggle {{ top: 10px; right: 12px; padding: 7px 12px; }}
        }}
        </style></head><body>
        <div class="controls">
            <div style="font-size: 1.2rem; font-weight: 900; color: var(--primary);">AssetScanner<span style="color:#94a3b8">Pro</span></div>
            <div class="search-box"><select id="searchType"><option value="ip">IP</option><option value="domain">Domain</option><option value="tech">Tech</option><option value="media">Media Type</option><option value="status">Status</option><option value="port">Port</option></select>
            <input type="text" id="searchInput" placeholder="Filter results..." oninput="doSearch()"></div>
            <button onclick="setAllGroups(true)">Expand All</button>
            <button onclick="setAllGroups(false)">Collapse All</button>
        </div>
        <div id="stickyBar" class="sticky-group-bar" onclick="collapseCurrent()">Group 1</div>
        <button type="button" id="sidebarToggle" class="sidebar-toggle" onclick="toggleSidebar()">Hide</button>
        <button id="backToTop" class="scroll-fab" onclick="scrollToTop()">▲</button>
        <button id="backToBottom" class="scroll-fab" onclick="scrollToBottom()">▼</button>
        <div class="container">{{content}}<footer class="report-footer">{self.esc(APP_NAME)} | {self.esc(VERSION)} | Attribution: <a href="{self.esc(ATTRIBUTION_URL)}" target="_blank" rel="noopener noreferrer">{self.esc(ATTRIBUTION_NAME)}</a></footer></div>
        <div id="lb" onclick="this.style.display='none'"><img id="l-img"></div>
        <script>
            let currentActiveId = null;
            let suppressCollapseJump = false;
            const SCROLL_OFFSET = 86;
            function zoom(s){{ document.getElementById('l-img').src = s; document.getElementById('lb').style.display = 'flex'; }}
            function scrollToTop() {{ window.scrollTo({{top: 0, behavior: 'smooth'}}); }}
            function scrollToBottom() {{ window.scrollTo({{top: document.documentElement.scrollHeight, behavior: 'smooth'}}); }}
            function groupSections() {{ return Array.from(document.querySelectorAll('.group-section')).filter(s => s.style.display !== 'none'); }}
            function scrollToGroup(sectionOrId) {{
                const section = typeof sectionOrId === 'string' ? document.getElementById(sectionOrId) : sectionOrId;
                if (!section) return;
                const top = section.getBoundingClientRect().top + window.scrollY - SCROLL_OFFSET;
                window.scrollTo({{top: Math.max(0, top), behavior: 'smooth'}});
            }}
            function jumpToGroup(id) {{
                const section = document.getElementById(id);
                if (!section) return;
                section.open = true;
                scrollToGroup(section);
                setActiveGroup(section);
            }}
            function toggleSidebar() {{
                const sidebar = document.getElementById('groupSidebar');
                const toggle = document.getElementById('sidebarToggle');
                sidebar.classList.toggle('collapsed');
                toggle.innerText = sidebar.classList.contains('collapsed') ? 'Groups' : 'Hide';
            }}
            function setActiveGroup(section) {{
                document.querySelectorAll('.group-section').forEach(s => s.classList.remove('active-group'));
                document.querySelectorAll('.side-nav-item').forEach(b => b.classList.remove('active'));
                if (!section) return;
                currentActiveId = section.id;
                section.classList.add('active-group');
                const nav = document.querySelector(`.side-nav-item[data-target="${{section.id}}"]`);
                if (nav) nav.classList.add('active');
            }}
            function setAllGroups(open) {{
                suppressCollapseJump = true;
                document.querySelectorAll('details').forEach(d => d.open = open);
                suppressCollapseJump = false;
                updateScrollState();
            }}
            function updateSidebarOrder() {{
                const list = document.querySelector('.side-nav-list');
                if (!list) return;
                const buttons = new Map(Array.from(document.querySelectorAll('.side-nav-item')).map(b => [b.dataset.target, b]));
                document.querySelectorAll('.group-section').forEach(section => {{
                    const btn = buttons.get(section.id);
                    if (btn) list.append(btn);
                }});
            }}
            function doSearch() {{
                const q = document.getElementById('searchInput').value.toLowerCase();
                const t = document.getElementById('searchType').value;
                document.querySelectorAll('.card').forEach(c => {{
                    const match = c.getAttribute('data-' + t).toLowerCase().includes(q);
                    c.style.display = match ? 'flex' : 'none';
                }});
                document.querySelectorAll('details').forEach(d => {{
                    const hasChild = Array.from(d.querySelectorAll('.card')).some(c => c.style.display !== 'none');
                    d.style.display = hasChild ? 'block' : 'none';
                }});
                updateScrollState();
            }}
            function updateScrollState() {{
                const sections = groupSections();
                const scrollPos = window.scrollY + 150; 
                const bar = document.getElementById('stickyBar');
                const btt = document.getElementById('backToTop');
                const btb = document.getElementById('backToBottom');
                const nearBottom = window.innerHeight + window.scrollY >= document.documentElement.scrollHeight - 80;
                btt.style.display = window.scrollY > 300 ? 'flex' : 'none';
                btb.style.display = nearBottom ? 'none' : 'flex';
                let current = null;
                sections.forEach(s => {{ if (s.offsetTop <= scrollPos) current = s; }});
                if (current && current.open) {{
                    bar.innerText = current.querySelector('.g-title').innerText;
                    bar.style.display = 'block';
                    setActiveGroup(current);
                }} else {{
                    bar.style.display = 'none';
                }}
            }}
            window.onscroll = updateScrollState;
            function collapseCurrent() {{
                if (currentActiveId) {{
                    const section = document.getElementById(currentActiveId);
                    if (!section) return;
                    section.open = false;
                    requestAnimationFrame(() => scrollToGroup(section));
                }}
            }}
            document.addEventListener('DOMContentLoaded', () => {{
                document.querySelectorAll('.group-section').forEach(section => {{
                    section.addEventListener('toggle', () => {{
                        if (!section.open && !suppressCollapseJump) requestAnimationFrame(() => scrollToGroup(section));
                        updateScrollState();
                    }});
                }});
                updateSidebarOrder();
                updateScrollState();
            }});
        </script></body></html>"""

def start_server(host, port, target_path):
    app = Flask(__name__)
    app.secret_key = secrets.token_hex(32)
    app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Lax')
    password = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(16))
    login_failures = {}
    target_abs = os.path.abspath(target_path)
    serve_dir = target_abs if os.path.isdir(target_abs) else os.path.dirname(target_abs)
    index_file = "index.html" if os.path.isdir(target_abs) else os.path.basename(target_abs)
    print(f"\n[*] WEB SERVER ACTIVE\n[*] URL: http://{host}:{port}/\n[*] PASSWORD: {password}\n")
    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'POST':
            client = request.remote_addr or "unknown"
            failures, last_failure = login_failures.get(client, (0, 0))
            if failures >= LOGIN_MAX_FAILURES and time.time() - last_failure < LOGIN_LOCKOUT_SECONDS:
                return "Too many failed attempts. Try again later.", 429
            if request.form.get('password') == password:
                session.clear()
                session['auth'] = True
                login_failures.pop(client, None)
                return redirect('/')
            login_failures[client] = (failures + 1, time.time())
            return "Unauthorized", 403
        return '<html><body style="display:flex;justify-content:center;align-items:center;height:100vh;background:#f1f5f9;"><form method="post" style="background:white;padding:30px;border-radius:10px;box-shadow:0 2px 10px rgba(0,0,0,0.1);"><h2>Login</h2><input type="password" name="password" style="padding:10px;margin-bottom:10px;width:200px;"><br><button type="submit" style="width:100%;padding:10px;background:#2563eb;color:white;border:none;border-radius:5px;cursor:pointer;">Access</button></form></body></html>'
    @app.route('/')
    def index():
        if not session.get('auth'): return redirect('/login')
        return send_from_directory(serve_dir, index_file)
    @app.route('/<path:filename>')
    def serve_static(filename):
        if not session.get('auth'): return redirect('/login')
        return send_from_directory(serve_dir, filename)
    logging.getLogger('werkzeug').setLevel(logging.ERROR)
    app.run(host=host, port=int(port), debug=False, threaded=True)

def parse_server_bind(value):
    value = (value or "").strip()
    if value.startswith('['):
        host, _, rest = value[1:].partition(']')
        if not host or not rest.startswith(':'):
            raise ValueError("invalid bracketed bind address")
        return host, rest[1:]
    host, sep, port = value.rpartition(':')
    if not sep or not host or ':' in host:
        raise ValueError("invalid bind address")
    return host, port

def ensure_dependencies(required):
    missing = [name for name in required if name in MISSING_DEPENDENCIES]
    if not missing:
        return
    print("[!] Missing required dependency/dependencies for this operation:")
    for name in sorted(set(missing)):
        print(f"    - {name}")
    print("\nInstall the full runtime set with:")
    print("    pip install imagehash requests urllib3 pillow beautifulsoup4 selenium webdriver-manager python-Wappalyzer flask tqdm")
    sys.exit(1)

class HelpFormatter(argparse.ArgumentDefaultsHelpFormatter, argparse.RawDescriptionHelpFormatter):
    pass

def main():
    global CHROME_DRIVER_PATH, WAPPALYZER_INST
    parser = argparse.ArgumentParser(
        prog="v3.py",
        formatter_class=HelpFormatter,
        description=USAGE_GUIDE,
    )
    parser.add_argument("--version", action="version", version=f"{APP_NAME} {VERSION} - {TAGLINE}")

    target_group = parser.add_argument_group("Target input")
    target_group.add_argument("-u", "--url", metavar="URL", help="scan a single target URL or host; scheme is optional")
    target_group.add_argument("-f", "--file", metavar="FILE", help="read target URLs/hosts from a text file, one per line")

    output_group = parser.add_argument_group("Output and serving")
    output_group.add_argument("-r", "--report", metavar="FILE", default="scanner_report.html", help="output HTML report path")
    output_group.add_argument("--server", metavar="IP:PORT", help="serve the report directory through a password-protected web UI")

    performance_group = parser.add_argument_group("Performance and browser tuning")
    performance_group.add_argument("-t", "--threads", metavar="N", type=int, default=4, help="number of concurrent browser workers; use 1-2 on low-resource servers")
    performance_group.add_argument("--timeout", metavar="SEC", type=int, default=45, help="maximum page-load time per target")
    performance_group.add_argument("--render-wait", metavar="SEC", type=float, default=0.6, help="extra wait after page readiness before screenshot capture")
    performance_group.add_argument("--retries", metavar="N", type=int, default=2, help="retry count per target after navigation or capture failure")
    performance_group.add_argument("--fast", action="store_true", help="low-resource mode: skip tech, geo, and HTTP preflight enrichment and block extra browser noise")
    performance_group.add_argument("--proxy", metavar="URL", help="HTTP/SOCKS proxy for browser and HTTP requests, for example http://127.0.0.1:8080")

    fingerprint_group = parser.add_argument_group("Fingerprinting and enrichment")
    fingerprint_group.add_argument("-s", "--similarity", metavar="0-10", type=int, default=5, help="visual similarity threshold used when grouping screenshots")
    fingerprint_group.add_argument("--no-tech", action="store_true", help="skip Wappalyzer technology detection")
    fingerprint_group.add_argument("--no-geo", action="store_true", help="skip DNS geo/ASN/CDN enrichment")
    fingerprint_group.add_argument("--no-http-check", action="store_true", help="skip the preflight HTTP status/content-type request")
    fingerprint_group.add_argument("--shodan-key", metavar="KEY", help="Shodan API key for enriching each IP with known open ports")
    fingerprint_group.add_argument("--no-shodan", action="store_true", help="disable Shodan port enrichment even when a key is available")
    fingerprint_group.add_argument("--fingerprints", metavar="FILE", default=DEFAULT_FINGERPRINT_DB, help="local JSON product fingerprint cache path")
    fingerprint_group.add_argument("--fingerprints-url", metavar="URL", help="custom remote JSON fingerprint database URL")
    fingerprint_group.add_argument("--no-auto-fingerprints", action="store_true", help="disable automatic online fingerprint database refresh")
    fingerprint_group.add_argument("--update-fingerprints", action="store_true", help="download and update the local fingerprint database, then optionally continue scanning")
    fingerprint_group.add_argument("--check-fingerprints-update", action="store_true", help="check whether the remote fingerprint database changed")

    debug_group = parser.add_argument_group("Diagnostics")
    debug_group.add_argument("--verbose", action="store_true", help="show non-fatal navigation and fingerprint warnings")

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)

    args = parser.parse_args()

    should_scan = bool(args.url or args.file)
    if not (should_scan or args.server or args.update_fingerprints or args.check_fingerprints_update):
        parser.print_help()
        sys.exit(0)

    if args.update_fingerprints or args.check_fingerprints_update:
        ensure_dependencies(["requests"])
        updater = UltraScanner(args)
        ok = updater.update_fingerprint_library(check_only=args.check_fingerprints_update and not args.update_fingerprints)
        if not (args.url or args.file or args.server):
            sys.exit(0 if ok else 1)

    if should_scan:
        scan_dependencies = ["imagehash", "requests", "urllib3", "Pillow", "beautifulsoup4", "selenium", "webdriver-manager"]
        if not (args.no_tech or args.fast):
            scan_dependencies.append("python-Wappalyzer")
        ensure_dependencies(scan_dependencies)
        print(BANNER)
        CHROME_DRIVER_PATH = ChromeDriverManager().install()
        WAPPALYZER_INST = None if (args.no_tech or args.fast) else Wappalyzer.latest()
        urls = []
        if args.url: urls.append(args.url)
        if args.file and os.path.exists(args.file):
            with open(args.file, 'r', encoding='utf-8') as f:
                urls.extend([line.strip() for line in f if line.strip()])
        
        if urls:
            pbar = tqdm(total=len(urls), desc="🚀 Scanning", unit="url", bar_format="{l_bar}{bar:30}{r_bar}{bar:-10b}")
            scanner = UltraScanner(args, pbar)
            interrupt_prompt_active = False
            
            def signal_handler(sig, frame):
                nonlocal interrupt_prompt_active
                if interrupt_prompt_active:
                    scanner.is_running = False
                    print("\n[!] Forced interruption. Saving partial report...")
                    scanner.generate_html()
                    sys.exit(130)
                interrupt_prompt_active = True
                try:
                    answer = input("\n[?] Ctrl+C detected. Stop scan and save partial report? [y/N]: ").strip().lower()
                finally:
                    interrupt_prompt_active = False
                if answer in ("y", "yes"):
                    scanner.is_running = False
                    print("\n[!] User confirmed interruption. Saving partial report...")
                    scanner.generate_html()
                    sys.exit(130)
                print("[*] Continuing scan...")
            signal.signal(signal.SIGINT, signal_handler)
            
            with ThreadPoolExecutor(max_workers=args.threads) as executor:
                work_queue = queue.Queue()
                for url in urls:
                    work_queue.put(url)
                futures = [executor.submit(scanner.worker_task, work_queue) for _ in range(max(1, args.threads))]
                for future in as_completed(futures):
                    if not scanner.is_running: break
                    try:
                        future.result()
                    except Exception as e:
                        scanner.log(f"[-] Worker failed: {str(e)[:80]}")
            
            pbar.close()
            if scanner.is_running: scanner.generate_html()
            
    if args.server:
        ensure_dependencies(["flask"])
        if not should_scan: print(BANNER)
        try:
            ip, port = parse_server_bind(args.server)
        except ValueError:
            print("[!] Server format: IP:PORT or [IPv6]:PORT")
        else:
            start_server(ip, port, args.report)

if __name__ == "__main__":
    main()
