#!/usr/bin/env python3
"""
VESPER - recon multitool for Ubuntu.

A menu-driven collection of discovery, scanning, identification,
web, DNS, crypto, network, wifi, file, local-audit and reporting
tools, plus a utility drawer.

Made by Zolo.

Run with sudo for DISCOVER, PORTSCAN, WIFI and LOCAL.
Indicators, not proof. A finding means "worth a look".
"""

import argparse
import base64
import binascii
import codecs
import hashlib
import ipaddress
import json
import math
import os
import re
import secrets
import shutil
import socket
import ssl
import string
import subprocess
import sys
import threading
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

NAME = "VESPER"
VERSION = "1.1"
AUTHOR = "Zolo"

C_RESET = "\033[0m"
C_DIM = "\033[2m"
C_BOLD = "\033[1m"
C_RED = "\033[31m"
C_RED_B = "\033[1;31m"
C_GREEN = "\033[32m"
C_YELLOW = "\033[33m"
C_CYAN = "\033[36m"
C_BLUE = "\033[34m"
C_MAGENTA = "\033[35m"

BANNER_ROWS = [
    "██╗   ██╗███████╗███████╗██████╗ ███████╗██████╗ ",
    "██║   ██║██╔════╝██╔════╝██╔══██╗██╔════╝██╔══██╗",
    "██║   ██║█████╗  █████╗  ██████╔╝█████╗  ██████╔╝",
    "╚██╗ ██╔╝██╔══╝  ██╔══╝  ██╔═══╝ ██╔══╝  ██╔══██╗",
    " ╚████╔╝ ███████╗███████╗██║     ███████╗██║  ██║",
    "  ╚═══╝  ╚══════╝╚══════╝╚═╝     ╚══════╝╚═╝  ╚═╝",
]

BANNER_COLORS = [
    "\033[36m",
    "\033[96m",
    "\033[94m",
    "\033[95m",
    "\033[35m",
    "\033[91m",
]

SEV_COLOR = {
    "CRITICAL": C_RED_B,
    "HIGH": C_RED,
    "MEDIUM": C_YELLOW,
    "LOW": C_CYAN,
    "INFO": C_DIM,
}

SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

DEFAULT_PAGE_MARKERS = [
    "Apache2 Ubuntu Default Page",
    "Welcome to nginx",
    "It works!",
    "IIS Windows Server",
    "Test Page for the Apache",
    "Default Web Site Page",
]

ADMIN_PATHS = [
    "/",
    "/admin",
    "/login",
    "/cgi-bin/luci",
    "/setup",
    "/management.html",
    "/admin.html",
]

CREDS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", ""),
    ("admin", "1234"),
    ("admin", "12345"),
    ("root", "root"),
    ("root", "admin"),
    ("user", "user"),
    ("support", "support"),
    ("admin", "admin123"),
    ("admin", "changeme"),
]

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
    993, 995, 1723, 3306, 3389, 5900, 8080,
]

DIR_WORDLIST = [
    "admin", "backup", "bak", "config", "console", "dashboard", "db",
    "dev", "download", "files", "images", "img", "includes", "install",
    "internal", "logs", "manage", "old", "panel", "phpinfo.php",
    "private", "robots.txt", "server-status", "setup", "sitemap.xml",
    "sql", "src", "staging", "static", "status", "test", "tmp",
    "upload", "uploads", "web.config", ".env", ".git/config", ".git/HEAD",
    ".htaccess", ".svn/entries", ".DS_Store", "crossdomain.xml",
]

SUBDOMAIN_WORDLIST = [
    "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2",
    "smtp", "secure", "vpn", "api", "dev", "staging", "test", "portal",
    "admin", "ftp", "git", "cloud", "cdn", "media", "static", "app",
    "dashboard", "db", "backup", "monitor", "status",
]

OUI_TABLE = {
    "00:72:EE": "Intel",
    "00:1A:11": "Google",
    "00:1B:63": "Apple",
    "00:1E:C2": "Apple",
    "3C:15:C2": "Apple",
    "F0:18:98": "Apple",
    "A4:83:E7": "Apple",
    "00:12:FB": "Samsung",
    "8C:77:12": "Samsung",
    "E8:50:8B": "Samsung",
    "5C:49:7D": "Samsung",
    "78:BD:BC": "Samsung",
    "24:0A:C4": "Espressif ESP32",
    "84:F3:EB": "Espressif ESP32",
    "A4:CF:12": "Espressif ESP32",
    "DC:4F:22": "Espressif ESP32",
    "18:FE:34": "Espressif ESP8266",
    "44:65:0D": "Amazon",
    "68:37:E9": "Amazon",
    "F0:27:2D": "Amazon",
    "74:C2:46": "Amazon",
    "38:F7:3D": "Amazon",
    "50:2E:5C": "Tuya",
    "68:57:2D": "Tuya",
    "D8:1F:12": "Tuya",
    "B8:27:EB": "Raspberry Pi",
    "DC:A6:32": "Raspberry Pi",
    "E4:5F:01": "Raspberry Pi",
    "00:1E:0B": "HP",
    "3C:D9:2B": "HP",
    "9C:B6:54": "HP",
    "00:00:0C": "Cisco",
    "00:1A:A1": "Cisco",
    "00:11:32": "Synology",
    "00:1A:8C": "Synology",
    "00:17:88": "Philips Hue",
    "EC:B5:FA": "Philips Hue",
    "B0:BE:76": "TP-Link",
    "50:C7:BF": "TP-Link",
    "00:0C:29": "VMware",
    "00:50:56": "VMware",
    "08:00:27": "VirtualBox",
    "00:15:5D": "Hyper-V",
    "F4:52:46": "Askey Computer (ISP CPE)",
}

HASH_LENGTHS = {
    32: "md5",
    40: "sha1",
    56: "sha224",
    64: "sha256",
    96: "sha384",
    128: "sha512",
}

MAGIC = {
    b"\x89PNG": "PNG image",
    b"\xff\xd8\xff": "JPEG image",
    b"GIF8": "GIF image",
    b"%PDF": "PDF document",
    b"PK\x03\x04": "ZIP or Office document",
    b"\x1f\x8b": "gzip archive",
    b"BZh": "bzip2 archive",
    b"\xfd7zXZ": "xz archive",
    b"7z\xbc\xaf": "7-zip archive",
    b"Rar!": "RAR archive",
    b"\x7fELF": "ELF executable",
    b"MZ": "Windows executable",
    b"\xca\xfe\xba\xbe": "Mach-O or Java class",
    b"SQLite format 3": "SQLite database",
    b"OggS": "Ogg media",
    b"ID3": "MP3 with ID3 tag",
    b"\x00\x00\x01\x00": "ICO icon",
}

RESULTS = []
HOSTS = []
DEVICES = {}
MACS = {}
TARGET = None
IFACE = None
GATEWAY = None
SAFE = False
NO_CLEAR = False
TIMEOUT = 1.5
BUDGET = 45.0
RUNNING = True
LOCK = threading.Lock()


# ---------------------------------------------------------------------------
# output helpers
# ---------------------------------------------------------------------------

def paint(text, color):
    return color + text + C_RESET


def clear():
    if NO_CLEAR:
        return
    sys.stdout.write("\033[H\033[2J\033[3J")
    sys.stdout.flush()


def pause():
    try:
        input(paint("   press enter ", C_DIM))
    except (EOFError, KeyboardInterrupt):
        print()


def ensure_terminal():
    if os.environ.get("VESPER_IN_TERM"):
        return False
    if sys.stdout.isatty():
        return False
    if "--no-window" in sys.argv:
        return False
    if "-h" in sys.argv or "--help" in sys.argv:
        return False
    if "-v" in sys.argv or "--version" in sys.argv:
        return False

    script = os.path.abspath(__file__)
    passthrough = []
    for item in sys.argv[1:]:
        if item != "--no-window":
            passthrough.append(item)

    candidates = [
        ("gnome-terminal", ["--"]),
        ("konsole", ["-e"]),
        ("xfce4-terminal", ["-e"]),
        ("mate-terminal", ["-e"]),
        ("lxterminal", ["-e"]),
        ("tilix", ["-e"]),
        ("alacritty", ["-e"]),
        ("kitty", []),
        ("xterm", ["-e"]),
    ]

    environment = os.environ.copy()
    environment["VESPER_IN_TERM"] = "1"

    for binary, prefix in candidates:
        if shutil.which(binary) is None:
            continue
        command = [binary] + prefix + [sys.executable, script] + passthrough
        try:
            subprocess.Popen(command, env=environment, start_new_session=True,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True
        except Exception:
            continue
    return False


def head(title):
    print()
    print(paint("── " + title + " " + "─" * max(0, 62 - len(title)), C_CYAN))


def note(text):
    print("   " + text)


def ok(text):
    print("   " + paint("[+] ", C_GREEN) + text)


def warn(text):
    print("   " + paint("[!] ", C_YELLOW) + text)


def bad(text):
    print("   " + paint("[-] ", C_RED) + text)


def dim(text):
    print(paint("   " + text, C_DIM))


def add(sev, host, title, detail, fix):
    with LOCK:
        RESULTS.append({
            "severity": sev,
            "host": host,
            "title": title,
            "detail": detail,
            "fix": fix,
            "when": datetime.now().isoformat(timespec="seconds"),
        })
    if host:
        line = paint("[" + sev + "] ", SEV_COLOR[sev]) + host + "  " + title
    else:
        line = paint("[" + sev + "] ", SEV_COLOR[sev]) + title
    print("   " + line)
    if detail:
        dim(detail)
    if fix:
        dim("fix: " + fix)


def count(sev):
    total = 0
    for item in RESULTS:
        if item["severity"] == sev:
            total = total + 1
    return total


def count_unknown():
    total = 0
    for host in HOSTS:
        if host not in DEVICES:
            total = total + 1
    return total


def splash():
    print()
    index = 0
    while index < len(BANNER_ROWS):
        print(BANNER_COLORS[index] + BANNER_ROWS[index] + C_RESET)
        index = index + 1
    print()
    print(C_DIM + "        light in the dark  ·  v" + VERSION + "  ·  made by " + AUTHOR + C_RESET)
    print(C_DIM + "        " + "─" * 46 + C_RESET)
    print("        target: " + (TARGET or "not set") + "        iface: " + (IFACE or "unknown"))
    print("        hosts: " + str(len(HOSTS)) + "  ·  critical: " + str(count("CRITICAL"))
          + "  ·  high: " + str(count("HIGH")) + "  ·  unknown: " + str(count_unknown()))
    print()


# ---------------------------------------------------------------------------
# shell and network helpers
# ---------------------------------------------------------------------------

def sh(cmd, timeout=120):
    try:
        done = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return done.stdout + done.stderr
    except Exception:
        return ""


def has(binary):
    return shutil.which(binary) is not None


def need(binary, package):
    if has(binary):
        return True
    warn(binary + " not installed - sudo apt install " + package)
    return False


def is_root():
    return os.geteuid() == 0


def default_iface():
    match = re.search(r"dev (\S+)", sh("ip -4 route show default"))
    if match:
        return match.group(1)
    return None


def local_cidr():
    route = sh("ip -4 route show default")
    match = re.search(r"dev (\S+)", route)
    if not match:
        return None, None, None
    dev = match.group(1)
    gateway = None
    gw_match = re.search(r"via (\d+\.\d+\.\d+\.\d+)", route)
    if gw_match:
        gateway = gw_match.group(1)
    addr = sh("ip -4 -o addr show dev " + dev)
    match = re.search(r"inet (\d+\.\d+\.\d+\.\d+)/(\d+)", addr)
    if not match:
        return None, None, gateway
    ip = match.group(1)
    prefix = int(match.group(2))
    ip_int = int.from_bytes(socket.inet_aton(ip), "big")
    mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
    net = socket.inet_ntoa((ip_int & mask).to_bytes(4, "big"))
    return net + "/" + str(prefix), ip, gateway


def ip_key(ip):
    parts = ip.split(".")
    return (int(parts[0]), int(parts[1]), int(parts[2]), int(parts[3]))


def sort_ips(items):
    ordered = list(items)
    ordered.sort(key=ip_key)
    return ordered


def is_private(ip):
    try:
        octets = [int(x) for x in ip.split(".")]
    except Exception:
        return False
    if octets[0] == 10:
        return True
    if octets[0] == 172 and 16 <= octets[1] <= 31:
        return True
    if octets[0] == 192 and octets[1] == 168:
        return True
    return False


def is_random_mac(mac):
    try:
        return bool(int(mac.split(":")[0], 16) & 0x02)
    except Exception:
        return False


def label(host, text):
    with LOCK:
        if host not in DEVICES:
            DEVICES[host] = set()
        DEVICES[host].add(text)


def resolve_target(required=True):
    global TARGET, IFACE, GATEWAY
    if TARGET:
        return TARGET
    cidr, me, gateway = local_cidr()
    if cidr is None:
        if required:
            warn("could not detect the local subnet - use 't' to set a target")
        return None
    TARGET = cidr
    GATEWAY = gateway
    IFACE = default_iface()
    ok("target set to " + cidr)
    return cidr


def ask(prompt_text, default=""):
    try:
        value = input("   " + prompt_text + ((" [" + default + "]") if default else "") + ": ")
    except EOFError:
        return default
    value = value.strip()
    if value == "":
        return default
    return value


def lookup_service(port):
    try:
        return socket.getservbyport(port, "tcp")
    except Exception:
        return "unknown"


# ---------------------------------------------------------------------------
# [1] DISCOVER
# ---------------------------------------------------------------------------

def ping_host(ip):
    done = subprocess.run(["ping", "-c1", "-W1", "-n", ip], capture_output=True)
    if done.returncode == 0:
        return ip
    return None


def ping_sweep(base):
    found = set()
    targets = []
    number = 1
    while number < 255:
        targets.append(base + "." + str(number))
        number = number + 1
    with ThreadPoolExecutor(max_workers=128) as pool:
        for result in pool.map(ping_host, targets):
            if result:
                found.add(result)
    return found


def do_discover(cidr, me):
    found = set()
    for line in sh("ip neigh").splitlines():
        match = re.match(r"(\d+\.\d+\.\d+\.\d+)", line)
        if match and "FAILED" not in line and "INCOMPLETE" not in line:
            found.add(match.group(1))

    if has("nmap"):
        output = sh("nmap -sn -PR -n --max-retries 1 --host-timeout 8s " + cidr, 900)
        for match in re.finditer(r"Nmap scan report for (\d+\.\d+\.\d+\.\d+)", output):
            found.add(match.group(1))
    elif has("arp-scan"):
        output = sh("arp-scan " + cidr + " --retry 2", 900)
        for line in output.splitlines():
            match = re.match(r"(\d+\.\d+\.\d+\.\d+)", line)
            if match:
                found.add(match.group(1))
    else:
        base = cidr.split("/")[0].rsplit(".", 1)[0]
        found = found | ping_sweep(base)

    if me and me in found:
        found.discard(me)
    return sort_ips(found)


def mod_discover():
    global HOSTS
    head("DISCOVER")
    cidr = resolve_target()
    if not cidr:
        return
    if not is_root() and not has("nmap"):
        warn("run as root for a reliable sweep")

    note("sweeping " + cidr)
    started = time.monotonic()
    hosts = do_discover(cidr, None)
    elapsed = time.monotonic() - started

    HOSTS = hosts
    ok(str(len(hosts)) + " live hosts in " + str(round(elapsed, 1)) + "s")
    if not hosts:
        return

    for host in hosts:
        label(host, "unidentified")

    print()
    for host in hosts:
        marker = ""
        if host == GATEWAY:
            marker = paint(" gateway", C_MAGENTA)
        print("   " + host + marker)
    add("INFO", "", "Discovery sweep", str(len(hosts)) + " hosts on " + cidr, "")


# ---------------------------------------------------------------------------
# [2] PORTSCAN
# ---------------------------------------------------------------------------

def scan_port(host, port):
    sock = socket.socket()
    sock.settimeout(TIMEOUT)
    try:
        if sock.connect_ex((host, port)) == 0:
            banner = ""
            try:
                sock.settimeout(1.0)
                raw = sock.recv(512)
                banner = raw.decode("latin-1", "replace").strip()
            except Exception:
                banner = ""
            return (port, banner)
        return None
    except Exception:
        return None
    finally:
        sock.close()


def scan_host(host, ports):
    open_ports = []

    def probe(port):
        return scan_port(host, port)

    with ThreadPoolExecutor(max_workers=64) as pool:
        for result in pool.map(probe, ports):
            if result:
                open_ports.append(result)
    open_ports.sort()
    return open_ports


def udp_probe(host, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(TIMEOUT)
    try:
        sock.sendto(b"\n", (host, port))
        sock.recvfrom(256)
        return True
    except socket.timeout:
        return False
    except Exception:
        return False
    finally:
        sock.close()


def mod_portscan():
    head("PORTSCAN")
    if not HOSTS:
        warn("no hosts yet - run DISCOVER first")
        return
    resolve_target()

    print("   presets: 1 top-20   2 1-1024   3 full   4 custom")
    choice = ask("preset", "1")
    ports = []
    if choice == "1":
        ports = list(COMMON_PORTS)
    elif choice == "2":
        ports = list(range(1, 1025))
    elif choice == "3":
        ports = list(range(1, 65536))
        warn("full scan of " + str(len(HOSTS)) + " hosts, this is slow")
    elif choice == "4":
        raw = ask("ports (comma separated)", "22,80,443")
        for piece in raw.split(","):
            piece = piece.strip()
            if piece.isdigit():
                ports.append(int(piece))
    else:
        ports = list(COMMON_PORTS)

    if not ports:
        warn("no ports selected")
        return

    do_udp = ask("include UDP probes for 53/123/161/1900/5353? y/N", "n").lower() == "y"

    note("scanning " + str(len(ports)) + " ports on " + str(len(HOSTS)) + " hosts")
    for host in HOSTS:
        started = time.monotonic()
        open_ports = scan_host(host, ports)
        elapsed = time.monotonic() - started
        if not open_ports:
            dim(host + "  no open ports  (" + str(round(elapsed, 1)) + "s)")
            continue
        print()
        print("   " + paint(host, C_BOLD) + "  " + str(len(open_ports)) + " open")
        for port, banner in open_ports:
            service = lookup_service(port)
            line = "     " + str(port) + "/tcp  " + service
            if banner:
                line = line + "  " + paint(banner[:70], C_DIM)
            print(line)
            label(host, service)
            add("INFO", host, "Open port " + str(port) + " (" + service + ")", banner[:100], "")
            if port == 23:
                add("MEDIUM", host, "Telnet exposed", "cleartext session", "use SSH instead")
            if port == 6379:
                add("LOW", host, "Redis port open", "verify authentication", "requirepass, bind localhost")
            if port == 3389:
                add("LOW", host, "RDP exposed", "check NLA and account lockout", "restrict by firewall")

        if do_udp and is_root():
            udp_ports = [53, 123, 161, 1900, 5353]
            for port in udp_ports:
                if udp_probe(host, port):
                    print("     " + str(port) + "/udp  responds")
                    add("INFO", host, "UDP " + str(port) + " responds", "", "")

        if elapsed > BUDGET:
            dim("host exceeded the budget of " + str(BUDGET) + "s")


# ---------------------------------------------------------------------------
# [3] IDENTIFY
# ---------------------------------------------------------------------------

def oui_vendor(mac):
    key = mac[:8].upper()
    if is_random_mac(mac):
        return "randomised MAC (phone or VM)"
    try:
        req = Request("https://api.macvendors.com/" + key, headers={"User-Agent": "vesper/1.1"})
        with urlopen(req, timeout=5) as response:
            vendor = response.read(120).decode("utf-8", "replace").strip()
            if vendor and "not found" not in vendor.lower():
                return vendor
    except Exception:
        pass
    if key in OUI_TABLE:
        return OUI_TABLE[key]
    return None


def mac_table():
    macs = {}
    for line in sh("ip neigh show").splitlines():
        match = re.match(r"(\d+\.\d+\.\d+\.\d+).*lladdr ([0-9a-fA-F:]{17})", line)
        if match:
            macs[match.group(1)] = match.group(2).lower()
    return macs


def netbios_name(host):
    if not has("nmblookup"):
        return None
    output = sh("nmblookup -A " + host, 15)
    match = re.search(r"^\s*(\S+)\s+<00>\s+-\s+B\s+<ACTIVE>", output, re.M)
    if match:
        return match.group(1)
    return None


def mdns_names(host):
    if not has("avahi-browse"):
        return []
    output = sh("avahi-browse -artp --timeout=3", 20)
    names = []
    for line in output.splitlines():
        if host in line:
            parts = line.split(";")
            if len(parts) > 3 and parts[3]:
                names.append(parts[3])
    return names


def tls_cert(host, port):
    try:
        pem = ssl.get_server_certificate((host, port))
    except Exception:
        return None
    if not has("openssl"):
        return None
    done = subprocess.run(
        ["openssl", "x509", "-noout", "-subject", "-issuer", "-dates", "-ext", "subjectAltName"],
        input=pem, capture_output=True, text=True)
    return done.stdout + done.stderr


def http_title(host, port, tls):
    scheme = "https" if tls else "http"
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    req = Request(scheme + "://" + host + ":" + str(port) + "/",
                  headers={"User-Agent": "vesper/1.1"})
    try:
        with urlopen(req, timeout=TIMEOUT + 1, context=context) as response:
            body = response.read(30000).decode("utf-8", "replace")
            server = response.headers.get("Server", "")
    except HTTPError as error:
        body = error.read(30000).decode("utf-8", "replace")
        server = ""
    except Exception:
        return None, None
    match = re.search(r"<title>(.*?)</title>", body, re.S | re.I)
    title = ""
    if match:
        title = match.group(1).strip()[:80]
    return title, server


def mod_identify():
    head("IDENTIFY")
    if not HOSTS:
        warn("no hosts yet - run DISCOVER first")
        return
    macs = mac_table()
    note("profiling " + str(len(HOSTS)) + " hosts")
    print()

    for host in HOSTS:
        parts = []
        mac = macs.get(host)
        if mac:
            with LOCK:
                MACS[host] = mac
            vendor = oui_vendor(mac)
            if vendor:
                parts.append(vendor)
                label(host, vendor)
        name = netbios_name(host)
        if name:
            parts.append("netbios:" + name)
            label(host, name)
        for mdns in mdns_names(host):
            parts.append("mdns:" + mdns)
            label(host, mdns)
        if host == GATEWAY:
            parts.append("gateway")
            label(host, "gateway")

        if parts:
            print("   " + paint(host, C_BOLD) + "  " + ", ".join(parts))
        else:
            dim(host + "  nothing resolved")

    print()
    if ask("dump TLS certificates where 443/8443 is open? y/N", "n").lower() == "y":
        for host in HOSTS:
            for port in (443, 8443):
                text = tls_cert(host, port)
                if text:
                    print()
                    print("   " + paint(host + ":" + str(port), C_BOLD))
                    for line in text.splitlines():
                        if line.strip():
                            dim(line)
                    if "self-signed" in text.lower() or "self signed" in text.lower():
                        add("LOW", host, "Self-signed certificate", "port " + str(port),
                            "install a real cert")

    if ask("fetch HTTP titles? y/N", "n").lower() == "y":
        for host in HOSTS:
            for port in (80, 8080, 8000, 443, 8443):
                title, server = http_title(host, port, port in (443, 8443))
                if title or server:
                    print("   " + host + ":" + str(port) + "  " + (server or "") + "  " + (title or ""))
                    if server:
                        add("INFO", host, "Server header", server, "")


# ---------------------------------------------------------------------------
# [4] WEB
# ---------------------------------------------------------------------------

def http_fetch(url, context=None, auth=None):
    req = Request(url, headers={"User-Agent": "vesper/1.1"})
    if auth:
        token = base64.b64encode((auth[0] + ":" + auth[1]).encode()).decode()
        req.add_header("Authorization", "Basic " + token)
    if context is None:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    try:
        with urlopen(req, timeout=TIMEOUT + 1, context=context) as response:
            return response.getcode(), response.read(40000).decode("utf-8", "replace"), dict(response.headers)
    except HTTPError as error:
        return error.code, error.read(40000).decode("utf-8", "replace"), dict(error.headers or {})
    except (URLError, socket.timeout, ssl.SSLError, OSError):
        return None, "", {}


def grade_tls(host, port):
    if not has("openssl"):
        warn("openssl missing")
        return
    for version in ("tls1", "tls1_1", "tls1_2", "tls1_3"):
        output = sh("echo | openssl s_client -connect " + host + ":" + str(port)
                    + " -" + version + " 2>&1 | grep -E 'Protocol|Cipher' | head -2", 20)
        if "Cipher" in output or "Protocol" in output:
            ok(version + " supported")
            if version in ("tls1", "tls1_1"):
                add("MEDIUM", host, "Weak TLS " + version, "offered", "require TLS 1.2+")
        else:
            dim(version + " refused")


def mod_web():
    head("WEB")
    host = ask("host", HOSTS[0] if HOSTS else "")
    if not host:
        return
    tls = ask("TLS? y/N", "n").lower() == "y"
    port = ask("port", "443" if tls else "80")
    if not port.isdigit():
        return
    scheme = "https" if tls else "http"
    base = scheme + "://" + host + ":" + port
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    code, body, headers = http_fetch(base + "/", context)
    if code is None:
        bad("no response from " + base)
        return

    print()
    note("status " + str(code))
    for key in headers:
        if key.lower() in ("server", "x-powered-by", "via", "location", "content-type", "set-cookie"):
            note(key + ": " + headers[key])

    title_match = re.search(r"<title>(.*?)</title>", body, re.S | re.I)
    if title_match:
        note("title: " + title_match.group(1).strip()[:80])

    for marker in DEFAULT_PAGE_MARKERS:
        if marker in body:
            add("LOW", host, "Default install page", marker, "configure the service")
            break
    if "Index of /" in body:
        add("MEDIUM", host, "Directory listing enabled", base + "/", "disable autoindex")

    print()
    if ask("brute common paths? y/N", "n").lower() == "y":
        for path in DIR_WORDLIST:
            path_code, path_body, _ = http_fetch(base + "/" + path, context)
            if path_code and path_code != 404:
                print("   " + str(path_code) + "  /" + path)
                if path_code == 200:
                    add("LOW", host, "Path reachable", "/" + path, "review exposure")
                if path == ".git/config" and path_code == 200:
                    add("HIGH", host, "Exposed git config", base + "/.git/config",
                        "block .git in the server config")
                if path == ".env" and path_code == 200:
                    add("HIGH", host, "Exposed .env", base + "/.env", "move it out of the web root")

    print()
    if not SAFE and ask("try default credentials on basic auth? y/N", "n").lower() == "y":
        for path in ADMIN_PATHS:
            code_now, _, _ = http_fetch(base + path, context)
            if code_now != 401:
                continue
            note("basic auth at " + path + ", trying defaults")
            for user, password in CREDS:
                test_code, _, _ = http_fetch(base + path, context, (user, password))
                if test_code and test_code not in (401, 403):
                    add("HIGH", host, "Default credentials accepted",
                        path + " accepts " + user + ":" + (password or "blank"),
                        "change the password")
                    break
            break

    print()
    if ask("TLS grade? y/N", "n").lower() == "y":
        grade_tls(host, port)


# ---------------------------------------------------------------------------
# [5] DNS
# ---------------------------------------------------------------------------

def dig(record, domain, server=None):
    if not has("dig"):
        return ""
    cmd = "dig +short " + record + " " + domain
    if server:
        cmd = "dig +short " + record + " " + domain + " @" + server
    return sh(cmd, 15)


def mod_dns():
    head("DNS")
    domain = ask("domain")
    if not domain:
        return
    if not need("dig", "dnsutils"):
        return

    for record in ("A", "AAAA", "MX", "TXT", "NS", "SOA", "CNAME"):
        output = dig(record, domain).strip()
        if output:
            print("   " + record + ":")
            for line in output.splitlines():
                dim("     " + line)

    print()
    note("SPF / DMARC")
    txt = dig("TXT", domain)
    if "v=spf1" in txt:
        ok("SPF present")
    else:
        add("LOW", domain, "No SPF record", "mail can be spoofed", "publish an SPF TXT record")
    dmarc = dig("TXT", "_dmarc." + domain)
    if "v=DMARC1" in dmarc:
        ok("DMARC present")
    else:
        add("LOW", domain, "No DMARC record", "no policy enforcement", "publish a DMARC record")

    print()
    if ask("attempt zone transfer? y/N", "n").lower() == "y":
        nameservers = dig("NS", domain).split()
        for server in nameservers:
            server = server.rstrip(".")
            output = sh("dig AXFR " + domain + " @" + server, 25)
            if "XFR size" in output:
                add("HIGH", domain, "Zone transfer allowed", "server " + server,
                    "restrict AXFR by IP")
                for line in output.splitlines()[:40]:
                    dim(line)
                break
            dim("refused by " + server)

    print()
    if ask("subdomain brute? y/N", "n").lower() == "y":
        for word in SUBDOMAIN_WORDLIST:
            candidate = word + "." + domain
            answer = dig("A", candidate).strip()
            if answer:
                print("   " + candidate + "  " + answer.splitlines()[0])
                add("INFO", domain, "Subdomain resolves", candidate, "")


# ---------------------------------------------------------------------------
# [6] CRYPTO
# ---------------------------------------------------------------------------

def mod_crypto():
    head("CRYPTO")
    print("   1 hash a string      2 hash a file     3 identify a hash")
    print("   4 encode             5 decode          6 JWT decode")
    print("   7 checksum a file")
    choice = ask("choice")

    if choice == "1":
        text = ask("string")
        if not text:
            return
        data = text.encode()
        for algorithm in ("md5", "sha1", "sha256", "sha512", "blake2b"):
            print("   " + algorithm.ljust(8) + " " + hashlib.new(algorithm, data).hexdigest())

    elif choice == "2":
        path = ask("file path")
        if not path or not os.path.isfile(path):
            bad("no such file")
            return
        for algorithm in ("md5", "sha1", "sha256", "sha512", "blake2b"):
            digest = hashlib.new(algorithm)
            with open(path, "rb") as handle:
                while True:
                    chunk = handle.read(65536)
                    if not chunk:
                        break
                    digest.update(chunk)
            print("   " + algorithm.ljust(8) + " " + digest.hexdigest())

    elif choice == "3":
        value = ask("hash")
        length = len(value.strip())
        if length in HASH_LENGTHS:
            ok("looks like " + HASH_LENGTHS[length])
        else:
            warn("length " + str(length) + " does not match a common hash")

    elif choice == "4":
        text = ask("string")
        print("   base64  " + base64.b64encode(text.encode()).decode())
        print("   hex     " + binascii.hexlify(text.encode()).decode())
        print("   url     " + urllib.parse.quote(text))
        print("   rot13   " + codecs.encode(text, "rot13"))

    elif choice == "5":
        print("   1 base64  2 hex  3 url  4 rot13")
        kind = ask("kind")
        text = ask("data")
        try:
            if kind == "1":
                print("   " + base64.b64decode(text).decode("utf-8", "replace"))
            elif kind == "2":
                print("   " + binascii.unhexlify(text).decode("utf-8", "replace"))
            elif kind == "3":
                print("   " + urllib.parse.unquote(text))
            elif kind == "4":
                print("   " + codecs.encode(text, "rot13"))
        except Exception:
            bad("could not decode that")

    elif choice == "6":
        token = ask("jwt")
        pieces = token.split(".")
        if len(pieces) < 2:
            bad("not a jwt")
            return
        for name, piece in (("header", pieces[0]), ("payload", pieces[1])):
            padded = piece + "=" * (-len(piece) % 4)
            try:
                decoded = base64.urlsafe_b64decode(padded).decode("utf-8", "replace")
                print("   " + name + ":")
                try:
                    print("     " + json.dumps(json.loads(decoded), indent=2).replace("\n", "\n     "))
                except Exception:
                    print("     " + decoded)
            except Exception:
                bad("could not decode " + name)
        if "alg" in token:
            note("check the alg field - 'none' and HS256 confusion are the usual bugs")

    elif choice == "7":
        path = ask("file path")
        if not path or not os.path.isfile(path):
            bad("no such file")
            return
        digest = hashlib.sha256()
        with open(path, "rb") as handle:
            while True:
                chunk = handle.read(65536)
                if not chunk:
                    break
                digest.update(chunk)
        print("   sha256  " + digest.hexdigest())
        note("compare against the vendor's published sum")


# ---------------------------------------------------------------------------
# [7] NET
# ---------------------------------------------------------------------------

def public_ip():
    try:
        with urlopen("https://api.ipify.org", timeout=5) as response:
            return response.read(60).decode().strip()
    except Exception:
        return None


def geoip(ip):
    try:
        with urlopen("http://ip-api.com/json/" + ip, timeout=6) as response:
            data = json.loads(response.read(2000).decode())
    except Exception:
        return None
    if data.get("status") != "success":
        return None
    return data


def mod_net():
    head("NET")
    print("   1 ping with stats   2 traceroute   3 MTU discovery")
    print("   4 whois             5 geolocation  6 public IP and ASN")
    print("   7 TTL based OS guess")
    choice = ask("choice")
    host = ""
    if choice != "6":
        host = ask("host")

    if choice == "1" and host:
        output = sh("ping -c 5 -W 2 " + host, 30)
        for line in output.splitlines():
            note(line)
        loss = re.search(r"(\d+(?:\.\d+)?)% packet loss", output)
        if loss and float(loss.group(1)) > 0:
            warn("packet loss detected")

    elif choice == "2" and host:
        if not need("traceroute", "traceroute"):
            return
        output = sh("traceroute -n -w 2 -q 1 " + host, 90)
        for line in output.splitlines():
            note(line)

    elif choice == "3" and host:
        note("binary searching the path MTU")
        low = 1200
        high = 1500
        while low < high:
            middle = (low + high + 1) // 2
            done = subprocess.run(
                ["ping", "-c1", "-W2", "-M", "do", "-s", str(middle - 28), host],
                capture_output=True)
            if done.returncode == 0:
                low = middle
            else:
                high = middle - 1
        ok("path MTU appears to be " + str(low))

    elif choice == "4" and host:
        if not need("whois", "whois"):
            return
        output = sh("whois " + host, 30)
        for line in output.splitlines():
            if line.strip() and not line.startswith("%"):
                note(line)
        if "Privacy" in output or "REDACTED" in output:
            dim("registrant details redacted")

    elif choice == "5" and host:
        data = geoip(host)
        if not data:
            bad("lookup failed")
            return
        note("country: " + str(data.get("country")))
        note("city: " + str(data.get("city")))
        note("isp: " + str(data.get("isp")))
        note("asn: " + str(data.get("as")))

    elif choice == "6":
        address = public_ip()
        if not address:
            bad("could not reach the lookup service")
            return
        note("public address: " + address)
        data = geoip(address)
        if data:
            note("asn: " + str(data.get("as")))
            note("isp: " + str(data.get("isp")))

    elif choice == "7" and host:
        output = sh("ping -c 1 " + host, 10)
        match = re.search(r"ttl=(\d+)", output)
        if not match:
            bad("no reply")
            return
        ttl = int(match.group(1))
        if ttl <= 64:
            guess = "Linux or Unix"
        elif ttl <= 128:
            guess = "Windows"
        else:
            guess = "network device"
        note("ttl " + str(ttl) + " - likely " + guess)
        note("this is a heuristic, hops reduce the value")


# ---------------------------------------------------------------------------
# [8] WIFI
# ---------------------------------------------------------------------------

def mod_wifi():
    head("WIFI")
    if not is_root():
        warn("needs root for a scan")
    interface = ask("interface", IFACE or "wlan0")

    output = ""
    if has("nmcli"):
        output = sh("nmcli -f SSID,BSSID,CHAN,SIGNAL,SECURITY device wifi list --rescan yes", 45)
    elif has("iw"):
        sh("ip link set " + interface + " up", 10)
        output = sh("iw dev " + interface + " scan", 45)
    else:
        if not need("iw", "iw"):
            return

    if not output.strip():
        bad("no results - check the interface name and that wifi is on")
        return

    networks = []
    if has("nmcli") and "SIGNAL" in output:
        for line in output.splitlines()[1:]:
            fields = re.split(r"\s{2,}", line.strip())
            if len(fields) >= 5:
                networks.append({
                    "ssid": fields[0] or "(hidden)",
                    "bssid": fields[1],
                    "channel": fields[2],
                    "signal": fields[3],
                    "security": fields[4],
                })
    else:
        current = {}
        for line in output.splitlines():
            stripped = line.strip()
            if stripped.startswith("BSS "):
                current = {"bssid": stripped.split()[1].split("(")[0], "ssid": "(hidden)"}
            elif stripped.startswith("SSID:"):
                current["ssid"] = stripped.split(":", 1)[1].strip()
            elif stripped.startswith("signal:"):
                current["signal"] = stripped.split(":", 1)[1].strip()
            elif stripped.startswith("DS Parameter set: channel"):
                current["channel"] = stripped.split()[-1]
                networks.append(current)
            elif stripped.startswith("RSN:"):
                current["security"] = "WPA2"
            elif stripped.startswith("WEP:"):
                current["security"] = "WEP"

    channels = {}
    print()
    for network in networks:
        ssid = network.get("ssid", "?")
        security = network.get("security", "open")
        channel = network.get("channel", "?")
        signal = network.get("signal", "?")
        line = "   " + ssid.ljust(28) + " ch " + str(channel).ljust(4) + " " + str(signal).ljust(6) + " " + security
        if security in ("", "open", "--"):
            print(line + paint("  OPEN", C_RED))
            add("MEDIUM", ssid, "Open network", "no encryption", "prefer WPA2 or WPA3")
        elif "WEP" in security:
            print(line + paint("  WEP", C_YELLOW))
            add("HIGH", ssid, "WEP encryption", "broken cipher", "move to WPA2")
        else:
            print(line)
        if ssid == "(hidden)":
            add("INFO", ssid, "Hidden SSID", network.get("bssid", ""), "cosmetic, not security")
        channels[channel] = channels.get(channel, 0) + 1

    print()
    note("channel congestion")
    for channel in sorted(channels, key=lambda c: str(c)):
        print("     ch " + str(channel).ljust(4) + paint("#" * channels[channel], C_CYAN))

    if ask("check for WPS enabled access points? y/N", "n").lower() == "y":
        if has("wash"):
            output = sh("wash -i " + interface + " -C", 45)
            if output.strip():
                for line in output.splitlines():
                    note(line)
                add("MEDIUM", "", "WPS access points found",
                    "WPS PIN attacks are often trivial", "disable WPS")
        else:
            warn("wash not installed - sudo apt install reaver")


# ---------------------------------------------------------------------------
# [9] FILES
# ---------------------------------------------------------------------------

def file_type(path):
    try:
        with open(path, "rb") as handle:
            header = handle.read(32)
    except Exception:
        return "unreadable"
    for signature in MAGIC:
        if header.startswith(signature):
            return MAGIC[signature]
    return "unknown"


def entropy(path):
    try:
        with open(path, "rb") as handle:
            data = handle.read(1048576)
    except Exception:
        return 0.0
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] = counts[byte] + 1
    total = len(data)
    score = 0.0
    for value in counts:
        if value:
            probability = value / total
            score = score - probability * math.log2(probability)
    return score


def mod_files():
    head("FILES")
    print("   1 identify type   2 strings   3 entropy   4 hexdump")
    print("   5 EXIF read       6 EXIF strip   7 directory size")
    choice = ask("choice")
    path = ask("path")
    if not path or not os.path.exists(path):
        bad("no such path")
        return

    if choice == "1":
        note("magic says: " + file_type(path))
        note("extension says: " + (os.path.splitext(path)[1] or "none"))
        if file_type(path) != "unknown" and os.path.splitext(path)[1]:
            dim("compare the two - a mismatch is worth a look")

    elif choice == "2":
        done = subprocess.run(["strings", "-n", "6", path], capture_output=True, text=True)
        lines = done.stdout.splitlines()
        for line in lines[:200]:
            note(line)
        note(str(len(lines)) + " total lines")

    elif choice == "3":
        score = entropy(path)
        note("entropy: " + str(round(score, 3)) + " bits per byte")
        if score > 7.5:
            add("INFO", os.path.basename(path), "High entropy file",
                str(round(score, 2)), "packed or encrypted")
            note("likely compressed or encrypted")
        elif score < 3:
            note("low entropy - text, sparse, or padded")

    elif choice == "4":
        with open(path, "rb") as handle:
            data = handle.read(512)
        offset = 0
        while offset < len(data):
            chunk = data[offset:offset + 16]
            hex_part = ""
            text_part = ""
            for byte in chunk:
                hex_part = hex_part + format(byte, "02x") + " "
                if 32 <= byte < 127:
                    text_part = text_part + chr(byte)
                else:
                    text_part = text_part + "."
            print("   " + format(offset, "08x") + "  " + hex_part.ljust(48) + text_part)
            offset = offset + 16

    elif choice == "5":
        if not need("exiftool", "libimage-exiftool-perl"):
            return
        output = sh("exiftool " + path, 30)
        for line in output.splitlines():
            note(line)
        if "GPS Position" in output:
            add("INFO", os.path.basename(path), "GPS coordinates in EXIF",
                "location leak", "strip before publishing")

    elif choice == "6":
        if not need("exiftool", "libimage-exiftool-perl"):
            return
        copy = path + ".clean"
        shutil.copy2(path, copy)
        sh("exiftool -all= -overwrite_original " + copy, 30)
        ok("written to " + copy)

    elif choice == "7":
        if not os.path.isdir(path):
            bad("not a directory")
            return
        total = 0
        for root, dirs, files in os.walk(path):
            for name in files:
                try:
                    total = total + os.path.getsize(os.path.join(root, name))
                except Exception:
                    pass
        note("total: " + str(round(total / 1048576, 2)) + " MB")


# ---------------------------------------------------------------------------
# [10] LOCAL
# ---------------------------------------------------------------------------

def mod_local():
    head("LOCAL")
    print("   1 listening sockets   2 established connections   3 SUID hunt")
    print("   4 cron and timers     5 sudo rights                6 world writable")
    print("   7 SSH keys")
    choice = ask("choice")

    if choice == "1":
        for line in sh("ss -tulpn", 20).splitlines():
            note(line)

    elif choice == "2":
        for line in sh("ss -tunp state established", 20).splitlines():
            note(line)

    elif choice == "3":
        warn("walking the filesystem, this takes a minute")
        output = sh("find / -xdev -perm -4000 -type f 2>/dev/null", 180)
        for line in output.splitlines():
            note(line)
        add("INFO", "", "SUID binaries", str(len(output.splitlines())) + " found",
            "compare against a known good baseline")

    elif choice == "4":
        output = sh("crontab -l 2>/dev/null; ls -1 /etc/cron.* 2>/dev/null; "
                    "systemctl list-timers --all --no-pager 2>/dev/null | head -30", 30)
        for line in output.splitlines():
            note(line)

    elif choice == "5":
        output = sh("sudo -n -l 2>/dev/null", 20)
        if not output.strip():
            warn("needs a password - run 'sudo -l' by hand")
        for line in output.splitlines():
            note(line)
            if "NOPASSWD" in line:
                add("LOW", "", "Passwordless sudo entry", line.strip(), "confirm it is intended")
        note(sh("id", 10).strip())

    elif choice == "6":
        warn("walking the filesystem")
        output = sh("find / -xdev -type f -perm -0002 2>/dev/null | head -80", 180)
        for line in output.splitlines():
            note(line)

    elif choice == "7":
        key_dir = os.path.expanduser("~/.ssh")
        if not os.path.isdir(key_dir):
            warn("no ~/.ssh directory")
            return
        for name in os.listdir(key_dir):
            if name.endswith(".pub"):
                path = os.path.join(key_dir, name)
                done = subprocess.run(["ssh-keygen", "-lf", path], capture_output=True, text=True)
                note(name + "  " + done.stdout.strip())


# ---------------------------------------------------------------------------
# [11] REPORT
# ---------------------------------------------------------------------------

def build_report():
    ordered = list(RESULTS)
    ordered.sort(key=lambda item: (SEV_ORDER[item["severity"]], item["host"]))
    return {
        "tool": NAME,
        "version": VERSION,
        "author": AUTHOR,
        "generated": datetime.now().isoformat(timespec="seconds"),
        "target": TARGET,
        "hosts": HOSTS,
        "devices": {key: sorted(value) for key, value in DEVICES.items()},
        "macs": MACS,
        "findings": ordered,
    }


def mod_report():
    head("REPORT")
    if not RESULTS:
        warn("nothing collected yet")
        return

    print("   1 summary   2 write JSON   3 write markdown   4 diff against a file")
    choice = ask("choice", "1")

    if choice == "1":
        print()
        for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            print("   " + paint(severity.ljust(9), SEV_COLOR[severity]) + str(count(severity)))
        print()
        for item in RESULTS:
            if item["severity"] == "INFO":
                continue
            print("   " + paint("[" + item["severity"] + "] ", SEV_COLOR[item["severity"]])
                  + item["host"] + "  " + item["title"])
            if item["detail"]:
                dim(item["detail"])

    elif choice == "2":
        path = ask("output file", "vesper-report.json")
        with open(path, "w") as handle:
            json.dump(build_report(), handle, indent=2)
        ok("written to " + path)

    elif choice == "3":
        path = ask("output file", "vesper-report.md")
        lines = []
        lines.append("# VESPER report")
        lines.append("")
        lines.append("Target: " + str(TARGET))
        lines.append("Generated: " + datetime.now().isoformat(timespec="seconds"))
        lines.append("")
        lines.append("| Severity | Host | Finding | Detail |")
        lines.append("| --- | --- | --- | --- |")
        for item in RESULTS:
            lines.append("| " + item["severity"] + " | " + item["host"] + " | "
                         + item["title"] + " | " + item["detail"].replace("|", "/") + " |")
        with open(path, "w") as handle:
            handle.write("\n".join(lines) + "\n")
        ok("written to " + path)

    elif choice == "4":
        path = ask("previous JSON file")
        if not path or not os.path.isfile(path):
            bad("no such file")
            return
        try:
            with open(path) as handle:
                old = json.load(handle)
        except Exception:
            bad("could not parse that file")
            return
        old_hosts = set(old.get("hosts", []))
        new_hosts = set(HOSTS)
        for host in sorted(new_hosts - old_hosts, key=ip_key):
            print("   " + paint("new host  ", C_GREEN) + host)
        for host in sorted(old_hosts - new_hosts, key=ip_key):
            print("   " + paint("gone      ", C_RED) + host)
        old_titles = set()
        for item in old.get("findings", []):
            old_titles.add(item["host"] + "|" + item["title"])
        for item in RESULTS:
            key = item["host"] + "|" + item["title"]
            if key not in old_titles:
                print("   " + paint("new finding  ", C_YELLOW) + item["host"] + "  " + item["title"])


# ---------------------------------------------------------------------------
# [12] UTIL
# ---------------------------------------------------------------------------

def mod_util():
    head("UTIL")
    print("   1 password   2 passphrase   3 CIDR calculator")
    print("   4 port lookup   5 QR code   6 epoch and base conversion")
    choice = ask("choice")

    if choice == "1":
        length = ask("length", "24")
        if not length.isdigit():
            length = "24"
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
        value = ""
        index = 0
        while index < int(length):
            value = value + secrets.choice(alphabet)
            index = index + 1
        print("   " + paint(value, C_GREEN))
        note("generated with secrets, not random")

    elif choice == "2":
        words = ["anchor", "beacon", "cipher", "delta", "ember", "fathom",
                 "granite", "harbor", "ivory", "juniper", "kestrel", "lantern",
                 "meridian", "nimbus", "onyx", "prism", "quartz", "raven",
                 "sable", "tundra", "umber", "vesper", "willow", "xenon",
                 "yarrow", "zephyr"]
        pieces = []
        index = 0
        while index < 4:
            pieces.append(secrets.choice(words))
            index = index + 1
        print("   " + paint("-".join(pieces) + "-" + str(secrets.randbelow(90) + 10), C_GREEN))

    elif choice == "3":
        cidr = ask("cidr", "192.168.1.0/24")
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except Exception:
            bad("not a valid network")
            return
        note("network:   " + str(network.network_address))
        note("broadcast: " + str(network.broadcast_address))
        note("netmask:   " + str(network.netmask))
        note("hosts:     " + str(network.num_addresses - 2))
        note("range:     " + str(network[1]) + " - " + str(network[-2]))

    elif choice == "4":
        value = ask("port or service")
        if value.isdigit():
            note(str(value) + " -> " + lookup_service(int(value)))
        else:
            for line in sh("grep -w '^" + value + "' /etc/services | head -5", 10).splitlines():
                note(line)

    elif choice == "5":
        text = ask("text")
        if not text:
            return
        if not need("qrencode", "qrencode"):
            return
        print(sh("qrencode -t ANSIUTF8 '" + text.replace("'", "") + "'", 15))

    elif choice == "6":
        print("   1 epoch to date   2 date to epoch   3 base conversion")
        kind = ask("kind")
        if kind == "1":
            value = ask("epoch seconds")
            if value.isdigit():
                note(datetime.fromtimestamp(int(value), tz=timezone.utc).isoformat())
        elif kind == "2":
            value = ask("date YYYY-MM-DD")
            try:
                stamp = datetime.strptime(value, "%Y-%m-%d").replace(tzinfo=timezone.utc)
                note(str(int(stamp.timestamp())))
            except Exception:
                bad("could not parse that date")
        elif kind == "3":
            value = ask("decimal")
            if value.isdigit():
                number = int(value)
                note("hex: " + hex(number))
                note("oct: " + oct(number))
                note("bin: " + bin(number))


# ---------------------------------------------------------------------------
# menu
# ---------------------------------------------------------------------------

MODULES = [
    ("1", "DISCOVER", "sweep the subnet for live hosts", mod_discover),
    ("2", "PORTSCAN", "TCP port scan with presets", mod_portscan),
    ("3", "IDENTIFY", "MAC, netbios, TLS cert, HTTP title", mod_identify),
    ("4", "WEB", "headers, paths, creds, TLS grade", mod_web),
    ("5", "DNS", "records, SPF, AXFR, subdomains", mod_dns),
    ("6", "CRYPTO", "hash, encode, decode, JWT", mod_crypto),
    ("7", "NET", "ping, traceroute, MTU, whois, geoip", mod_net),
    ("8", "WIFI", "access points and channel congestion", mod_wifi),
    ("9", "FILES", "type, strings, entropy, EXIF", mod_files),
    ("10", "LOCAL", "sockets, SUID, cron, sudo, keys", mod_local),
    ("11", "REPORT", "summary, JSON, markdown, diff", mod_report),
    ("12", "UTIL", "passwords, CIDR, QR, conversions", mod_util),
]


def draw_menu():
    print()
    print(paint("  ┌──────────────────────────────────────────────────────┐", C_DIM))
    for key, name, description, _ in MODULES:
        number = key.rjust(2)
        padding = 54 - (16 + len(description))
        if padding < 0:
            padding = 0
        line = ("  " + paint("│", C_DIM) + " " + number + "  "
                + paint(name.ljust(10), C_BOLD) + " " + description
                + " " * padding + paint("│", C_DIM))
        print(line)
    print(paint("  ├──────────────────────────────────────────────────────┤", C_DIM))
    bar = " t target   s safe mode   h hosts   r report   q quit"
    print("  " + paint("│", C_DIM) + bar.ljust(54) + paint("│", C_DIM))
    print(paint("  └──────────────────────────────────────────────────────┘", C_DIM))
    print("   " + C_DIM + "safe: " + ("on" if SAFE else "off") + "  ·  "
          + str(len(RESULTS)) + " findings  ·  " + str(len(HOSTS)) + " hosts" + C_RESET)


def show_hosts():
    if not HOSTS:
        warn("no hosts yet")
        return
    print()
    for host in HOSTS:
        tags = ""
        if host in DEVICES:
            tags = ", ".join(sorted(DEVICES[host]))
        print("   " + host.ljust(16) + C_DIM + tags + C_RESET)


def menu_loop():
    global SAFE, TARGET
    first = True
    while RUNNING:
        if not first:
            clear()
        first = False
        draw_menu()
        try:
            choice = input(paint("  vesper> ", C_CYAN)).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return
        if choice in ("q", "quit", "exit"):
            return
        if choice == "t":
            value = ask("target CIDR")
            if value:
                TARGET = value
                ok("target set to " + value)
            pause()
            continue
        if choice == "s":
            SAFE = not SAFE
            if SAFE:
                warn("safe mode on - no authentication attempts")
            else:
                ok("safe mode off")
            pause()
            continue
        if choice == "h":
            show_hosts()
            pause()
            continue
        if choice == "r":
            mod_report()
            pause()
            continue

        matched = None
        for key, name, description, function in MODULES:
            if choice == key or choice.lower() == name.lower():
                matched = function
                break
        if matched is None:
            warn("no such option")
            pause()
            continue
        try:
            matched()
        except KeyboardInterrupt:
            print()
            warn("module interrupted")
        except Exception as error:
            bad("module failed: " + str(error))
        pause()


# ---------------------------------------------------------------------------
# entry point
# ---------------------------------------------------------------------------

def main():
    global TARGET, IFACE, GATEWAY, SAFE, TIMEOUT, BUDGET, NO_CLEAR

    if ensure_terminal():
        return

    parser = argparse.ArgumentParser(
        prog="vesper",
        description="VESPER recon multitool. Run with no arguments for the menu.")
    parser.add_argument("-t", "--target", help="CIDR to work against")
    parser.add_argument("-m", "--module", help="run one module by name and exit")
    parser.add_argument("--safe", action="store_true", help="skip authentication attempts")
    parser.add_argument("--timeout", type=float, default=1.5, help="connect timeout in seconds")
    parser.add_argument("--budget", type=float, default=45.0, help="seconds per host before checks stop")
    parser.add_argument("--json", metavar="FILE", help="write a JSON report on exit")
    parser.add_argument("--no-clear", action="store_true", help="do not clear between modules")
    parser.add_argument("--no-window", action="store_true", help="do not open a new window")
    parser.add_argument("-v", "--version", action="version", version=NAME + " " + VERSION)
    args = parser.parse_args()

    SAFE = args.safe
    TIMEOUT = args.timeout
    BUDGET = args.budget
    NO_CLEAR = args.no_clear
    IFACE = default_iface()
    GATEWAY = None

    if args.target:
        TARGET = args.target
        found, me, gateway = local_cidr()
        if gateway:
            GATEWAY = gateway
        if found:
            IFACE = default_iface()

    clear()
    splash()

    if args.module:
        wanted = args.module.lower()
        for key, name, description, function in MODULES:
            if wanted == name.lower() or wanted == key:
                function()
                if args.json:
                    with open(args.json, "w") as handle:
                        json.dump(build_report(), handle, indent=2)
                    ok("written to " + args.json)
                return
        bad("no module called " + args.module)
        return

    if not is_root():
        dim("not root - DISCOVER, PORTSCAN, WIFI and LOCAL will be limited")

    menu_loop()

    if args.json:
        with open(args.json, "w") as handle:
            json.dump(build_report(), handle, indent=2)
        ok("report written to " + args.json)

    print()
    print(paint("  " + str(len(RESULTS)) + " findings collected. Stay curious.", C_DIM))
    print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print()
        print(paint("  interrupted", C_DIM))
