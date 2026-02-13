#!/usr/bin/env python3

import os
import sys
import json
import time
import subprocess
import re
import socket
import requests
from datetime import datetime, timedelta, UTC
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Version
CURRENT_VERSION = "v1.2"

# Configuration
VENDOR_DB_URL = "https://www.wireshark.org/download/automated/data/manuf"
VENDOR_DB_PATH = "/tmp/device-vendors.txt"
STATE_FILE = "/tmp/network_scanner_state.json"
VERSION_CACHE_FILE = "/tmp/version_cache.json"
VERSION_CHECK_INTERVAL = 3600  # Check for updates every hour
BYTE_LIMIT = int(os.getenv("BYTE_LIMIT", "2000"))
PLUGIN_UUID = os.getenv("PLUGIN_UUID", "")
INTERVAL = int(os.getenv("INTERVAL", "15"))
NETWORK = os.getenv("NETWORK", "")
OFFLINE_RETENTION = int(os.getenv("OFFLINE_RETENTION", "1440"))  # Default 24 hours in minutes
ENABLE_PORT_SCAN = os.getenv("ENABLE_PORT_SCAN", "false").lower() in ['true', '1', 'yes']
PORT_SCAN_PORTS = os.getenv("PORT_SCAN_PORTS", "22,80,443,8080,3389,5900,9000")  # Default common ports


class Colors:
    GREEN = '\033[0;32m'
    BLUE = '\033[0;34m'
    YELLOW = '\033[1;33m'
    RED = '\033[0;31m'
    NC = '\033[0m'


def log(message: str, color: str = Colors.NC):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    print(f"{color}[{timestamp}] {message}{Colors.NC}", file=sys.stderr)


def download_vendor_db():
    """Download the Wireshark OUI database"""
    if Path(VENDOR_DB_PATH).exists():
        # Check if file is older than 7 days
        mtime = Path(VENDOR_DB_PATH).stat().st_mtime
        if time.time() - mtime < 7 * 86400:
            return

    log("Downloading vendor database...", Colors.YELLOW)
    try:
        response = requests.get(VENDOR_DB_URL, timeout=30)
        response.raise_for_status()
        with open(VENDOR_DB_PATH, 'w') as f:
            f.write(response.text)
        log("Vendor database downloaded successfully", Colors.GREEN)
    except Exception as e:
        log(f"Failed to download vendor database: {e}", Colors.RED)
        # Create empty file so script continues
        Path(VENDOR_DB_PATH).touch()


def get_current_version() -> str:
    """Get current version from local version.json"""
    try:
        local_version_file = Path(__file__).parent / 'version.json'
        if local_version_file.exists():
            with open(local_version_file, 'r') as f:
                version_data = json.load(f)

            if 'versions' in version_data and len(version_data['versions']) > 0:
                return version_data['versions'][0]['version']
    except Exception as e:
        log(f"Could not read local version.json: {e}", Colors.YELLOW)

    # Fallback to hardcoded version
    return CURRENT_VERSION


def get_latest_version() -> Optional[str]:
    """Fetch latest version from GitHub using repo/branch from local version.json"""
    try:
        # Check cache first
        if Path(VERSION_CACHE_FILE).exists():
            try:
                with open(VERSION_CACHE_FILE, 'r') as f:
                    cache = json.load(f)
                    cache_time = cache.get('timestamp', 0)
                    if time.time() - cache_time < VERSION_CHECK_INTERVAL:
                        return cache.get('latest_version')
            except:
                pass

        # Get repo and branch from local version.json
        local_version_file = Path(__file__).parent / 'version.json'
        if not local_version_file.exists():
            log("No local version.json - skipping version check", Colors.YELLOW)
            return None

        with open(local_version_file, 'r') as f:
            version_data = json.load(f)

        repo = version_data.get('repo')
        branch = version_data.get('branch')

        if not repo or not branch:
            log("No repo/branch in version.json - skipping version check", Colors.YELLOW)
            return None

        # Fetch from GitHub
        version_url = f"https://raw.githubusercontent.com/{repo}/refs/heads/{branch}/version.json"

        log(f"Checking for updates from {repo} ({branch})...", Colors.BLUE)
        response = requests.get(version_url, timeout=10)
        response.raise_for_status()

        remote_version_data = response.json()

        if 'versions' in remote_version_data and len(remote_version_data['versions']) > 0:
            latest_version = remote_version_data['versions'][0]['version']

            # Cache the result
            try:
                with open(VERSION_CACHE_FILE, 'w') as f:
                    json.dump({
                        'latest_version': latest_version,
                        'timestamp': time.time()
                    }, f)
            except:
                pass

            return latest_version

    except Exception as e:
        log(f"Failed to fetch latest version: {e}", Colors.YELLOW)

    return None


def lookup_vendor(mac: str) -> str:
    """Look up vendor by MAC address OUI"""
    if not mac:
        return ""

    try:
        # Get first 3 octets (OUI)
        oui = ':'.join(mac.upper().split(':')[:3])

        with open(VENDOR_DB_PATH, 'r', errors='ignore') as f:
            for line in f:
                if line.startswith('#') or not line.strip():
                    continue

                parts = line.strip().split('\t')
                if len(parts) >= 2 and parts[0].upper().startswith(oui):
                    # Return long name if available, otherwise short name
                    vendor = parts[2] if len(parts) >= 3 else parts[1]

                    # Clean up common non-vendor entries - return empty for these
                    vendor_lower = vendor.lower()
                    if any(x in vendor_lower for x in ['unknown', 'private', 'locally administered']):
                        return ""

                    return vendor

        return ""
    except Exception as e:
        log(f"Error looking up vendor for {mac}: {e}", Colors.RED)
        return ""


def scan_ports(ip: str, ports: List[int]) -> List[int]:
    """Scan specified ports on an IP address"""
    open_ports = []

    if not ports:
        return open_ports

    # Don't scan too many ports at once
    if len(ports) > 20:
        log(f"  Too many ports ({len(ports)}) to scan for {ip}, limiting to first 20", Colors.YELLOW)
        ports = ports[:20]

    try:
        # Method 1: Try nmap first (faster)
        try:
            port_arg = ','.join(str(p) for p in ports)
            result = subprocess.run(
                ['nmap', '-p', port_arg, '-T4', '--max-retries', '1', '--host-timeout', '10s', '-Pn', ip],
                capture_output=True,
                text=True,
                timeout=45
            )

            # Parse nmap output for open ports
            for line in result.stdout.split('\n'):
                match = re.match(r'(\d+)/tcp\s+open', line)
                if match:
                    port = int(match.group(1))
                    open_ports.append(port)

            if open_ports:
                log(f"  Found open ports on {ip}: {', '.join(str(p) for p in open_ports)}", Colors.GREEN)
                return open_ports

        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            # Nmap timed out or not installed, fall back to socket scan
            if isinstance(e, FileNotFoundError):
                log(f"  nmap not installed, using socket fallback", Colors.YELLOW)
            else:
                log(f"  nmap timeout for {ip}, using socket fallback", Colors.YELLOW)

        # Method 2: Socket fallback - FIXED VERSION
        log(f"  Scanning {len(ports)} ports on {ip} with socket...", Colors.BLUE)

        for port in ports:
            try:
                # Create a new socket for each connection
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)  # 500ms timeout per port
                result = sock.connect_ex((ip, port))
                sock.close()

                if result == 0:
                    open_ports.append(port)
                    log(f"  Found open port {port} on {ip}", Colors.GREEN)
            except Exception as e:
                # Silently fail for connection errors
                pass

        if open_ports:
            log(f"  Socket scan found open ports on {ip}: {', '.join(str(p) for p in open_ports)}", Colors.GREEN)

    except Exception as e:
        log(f"  Error scanning ports on {ip}: {e}", Colors.RED)

    return open_ports

def get_port_list() -> List[int]:
    """Parse the PORT_SCAN_PORTS configuration into a list of ports"""
    if PORT_SCAN_PORTS.strip().lower() == 'all':
        # Scan all 65535 ports (this will be VERY slow)
        return list(range(1, 65536))

    ports = []
    try:
        for part in PORT_SCAN_PORTS.split(','):
            part = part.strip()
            if '-' in part:
                # Handle range like "80-90"
                start, end = part.split('-')
                ports.extend(range(int(start), int(end) + 1))
            else:
                # Single port
                ports.append(int(part))

        # Remove duplicates and sort
        ports = sorted(set(ports))

    except ValueError as e:
        log(f"Invalid port configuration: {e}. Using default ports.", Colors.RED)
        # Default fallback
        ports = [22, 80, 443, 8080, 3389, 5900, 9000]

    return ports


def resolve_hostname(ip: str, state: Dict) -> str:
    """Resolve hostname for an IP address using multiple methods"""

    # Check cache first
    if ip in state:
        cached_hostname = state[ip].get('hostname', '')
        if cached_hostname and cached_hostname != ip:
            return cached_hostname

    hostname = ip

    try:
        # Method 1: Socket reverse DNS
        hostname = socket.gethostbyaddr(ip)[0]
        if hostname != ip:
            return hostname
    except:
        pass

    try:
        # Method 2: host command
        result = subprocess.run(['host', ip], capture_output=True, text=True, timeout=2)
        if result.returncode == 0:
            match = re.search(r'domain name pointer (.+?)\.?$', result.stdout, re.MULTILINE)
            if match:
                hostname = match.group(1)
                if hostname != ip:
                    return hostname
    except:
        pass

    try:
        # Method 3: avahi for .local hostnames
        result = subprocess.run(['avahi-resolve-address', ip],
                                capture_output=True, text=True, timeout=2)
        if result.returncode == 0:
            parts = result.stdout.strip().split()
            if len(parts) >= 2:
                hostname = parts[1]
                if hostname != ip:
                    return hostname
    except:
        pass

    return hostname


def detect_device_type(hostname: str, vendor: str, open_ports: List[int] = None) -> str:
    """Detect device type based on hostname, vendor, and open ports"""
    h = hostname.lower()
    v = vendor.lower()
    ports = open_ports or []

    # Check for Android/iOS device patterns first (before checking vendor)
    # These devices often use MAC randomization, so vendor might be "locally administered"
    if any(x in h for x in
           ['android', 'phone', 'mobile', 'tablet', 'ipad', 'iphone', 'galaxy', 'pixel', 'oneplus', 'xiaomi', 'oppo',
            'vivo', 'realme', 'samsung-', 'huawei']):
        return "Mobile Device"

    # Port-based detection (checked early as it's very reliable)
    if 3389 in ports:  # RDP
        return "Windows Computer"
    if 5900 in ports:  # VNC
        return "Computer (VNC)"
    if 22 in ports and (80 in ports or 443 in ports):
        # SSH + web suggests server/router
        if any(x in v for x in ['tp-link', 'netgear', 'linksys', 'asus', 'ubiquiti', 'd-link']):
            return "Router"
        return "Server"
    if 631 in ports:  # IPP (Internet Printing Protocol)
        return "Printer"

    # Routers and Network Equipment
    if any(x in v for x in ['tp-link', 'netgear', 'linksys', 'asus', 'ubiquiti', 'unifi', 'd-link', 'sagemcom']):
        return "Router"
    if any(x in h for x in ['router', 'gateway', 'modem', 'access', 'point']):
        return "Router"

    # Raspberry Pi
    if 'raspberry' in v or any(x in h for x in ['raspberry', 'pi', 'pihole']):
        return "Raspberry Pi"

    # Printers
    if any(x in v for x in ['brother', 'hp', 'epson', 'canon', 'lexmark']):
        return "Printer"
    if 'printer' in h:
        return "Printer"

    # Smart Home
    if any(x in v for x in ['tuya', 'philips', 'hue', 'wyze']):
        return "Smart Device"
    if any(x in h for x in ['smart', 'hue', 'bulb', 'plug', 'switch']):
        return "Smart Device"

    # Speakers
    if any(x in v for x in ['sonos', 'bose', 'slim']):
        return "Speaker"
    if any(x in h for x in ['speaker', 'sonos', 'squeezebox']):
        return "Speaker"

    # Apple
    if 'apple' in v or any(x in h for x in ['iphone', 'ipad', 'macbook', 'imac', 'airpod']):
        return "Apple Device"

    # Google
    if 'google' in v or any(x in h for x in ['chromecast', 'nest', 'google', 'home']):
        return "Google Device"

    # Samsung
    if 'samsung' in v or 'galaxy' in h:
        return "Samsung Device"

    # Computers
    if any(x in h for x in ['desktop', 'laptop', 'pc', 'macbook', 'imac', 'surface']):
        return "Computer"

    # Gaming
    if any(x in v for x in ['sony', 'microsoft', 'nintendo', 'valve']):
        return "Gaming Console"
    if any(x in h for x in ['playstation', 'xbox', 'ps4', 'ps5', 'switch', 'steamdeck']):
        return "Gaming Console"

    # TV/Streaming
    if any(x in v for x in ['roku', 'nvidia', 'lg', 'vizio']):
        return "TV/Streaming"
    if any(x in h for x in ['tv', 'roku', 'shield', 'appletv']):
        return "TV/Streaming"

    # Cameras
    if 'camera' in h or 'cam' in h or 'doorbell' in h:
        return "Camera"

    # NAS
    if any(x in h for x in ['nas', 'storage', 'synology', 'qnap']):
        return "NAS"

    # Virtual Machines / Docker (check last, after all real devices)
    if any(x in v for x in ['vmware', 'virtualbox', 'qemu', 'xen', 'parallels']):
        return "Virtual Machine"
    if any(x in h for x in ['vm-', 'docker', 'container', 'virtual']):
        return "Virtual Machine"

    # If vendor is "locally administered" and we haven't matched anything else,
    # it's probably a mobile device with MAC randomization
    if 'locally administered' in v:
        return "Mobile Device"

    return ""


def get_local_mac(ip: str) -> Optional[str]:
    """Get MAC address for local IP from network interfaces"""
    try:
        result = subprocess.run(['ip', 'addr', 'show'],
                                capture_output=True, text=True, timeout=5)
        if result.returncode != 0:
            return None

        lines = result.stdout.split('\n')
        current_ip = None

        for line in lines:
            # Check for IP address
            ip_match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)', line)
            if ip_match:
                current_ip = ip_match.group(1)

            # Check for MAC address
            if current_ip == ip:
                mac_match = re.search(r'link/ether ([0-9a-f:]+)', line)
                if mac_match:
                    return mac_match.group(1).upper()

        return None
    except:
        return None


def get_host_ip(interface: str) -> Optional[str]:
    """Get IP address of the host on the specified interface"""
    try:
        result = subprocess.run(['ip', '-4', 'addr', 'show', interface],
                               capture_output=True, text=True, timeout=5)
        match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)', result.stdout)
        return match.group(1) if match else None
    except:
        return None

def get_host_mac(interface: str) -> Optional[str]:
    """Get MAC address of the host on the specified interface"""
    try:
        result = subprocess.run(['ip', 'link', 'show', interface],
                               capture_output=True, text=True, timeout=5)
        match = re.search(r'link/ether ([0-9a-f:]+)', result.stdout, re.IGNORECASE)
        return match.group(1).upper() if match else None
    except:
        return None

def scan_arp() -> List[Dict]:
    """Scan network using arp-scan"""
    devices = []

    try:
        # Get default interface
        result = subprocess.run(['ip', 'route'], capture_output=True, text=True, timeout=5)
        interface_match = re.search(r'default.*dev (\S+)', result.stdout)
        if not interface_match:
            log("Could not determine default interface", Colors.YELLOW)
            return devices

        interface = interface_match.group(1)
        network = NETWORK if NETWORK else auto_detect_network()

        log(f"Running arp-scan on {interface} for {network}", Colors.BLUE)
        result = subprocess.run(['arp-scan', '--interface', interface, network],
                                capture_output=True, text=True, timeout=60)

        for line in result.stdout.split('\n'):
            # Match lines with IP, MAC, and optionally vendor
            match = re.match(r'(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f:]+)\s*(.*)', line, re.IGNORECASE)
            if match:
                ip = match.group(1)
                mac = match.group(2).upper()
                vendor = match.group(3).strip() if match.group(3) else lookup_vendor(mac)

                devices.append({
                    'ip': ip,
                    'mac': mac,
                    'vendor': vendor  # Can be empty string
                })

        # Add the host itself (the machine running the scan)
        host_ip = get_host_ip(interface)
        host_mac = get_host_mac(interface)
        if host_ip and host_mac:
            # Check if we already added this host (shouldn't happen, but just in case)
            if not any(d['ip'] == host_ip for d in devices):
                host_vendor = lookup_vendor(host_mac) or ""
                devices.append({
                    'ip': host_ip,
                    'mac': host_mac,
                    'vendor': host_vendor
                })
                log(f"Added local host: {host_ip} ({host_mac})", Colors.BLUE)

        log(f"arp-scan found {len(devices)} devices", Colors.GREEN)
    except Exception as e:
        log(f"arp-scan failed: {e}", Colors.YELLOW)

    return devices

def scan_nmap() -> List[Dict]:
    """Scan network using nmap"""
    devices = []

    try:
        network = NETWORK if NETWORK else auto_detect_network()
        log(f"Running nmap on {network}", Colors.BLUE)

        # Reduced timeout and more aggressive settings for faster scans
        result = subprocess.run(['nmap', '-sn', '-T5', '--host-timeout', '10s',
                                 '--max-retries', '1', network],
                                capture_output=True, text=True, timeout=60)

        current_device = {}

        for line in result.stdout.split('\n'):
            # Nmap scan report line
            if 'Nmap scan report for' in line:
                if current_device and 'ip' in current_device:
                    devices.append(current_device)

                # Extract IP
                ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                if ip_match:
                    ip = ip_match.group(1)
                    # Extract hostname if present
                    hostname_match = re.match(r'Nmap scan report for (.+?) \(', line)
                    hostname = hostname_match.group(1) if hostname_match else ip

                    current_device = {
                        'ip': ip,
                        'hostname': hostname,
                        'mac': '',
                        'vendor': ''
                    }

            # MAC address line
            elif 'MAC Address:' in line and current_device:
                mac_match = re.search(r'MAC Address: ([0-9A-F:]+)', line, re.IGNORECASE)
                if mac_match:
                    mac = mac_match.group(1).upper()
                    vendor_match = re.search(r'\((.+)\)', line)
                    vendor = vendor_match.group(1) if vendor_match else lookup_vendor(mac)

                    current_device['mac'] = mac
                    current_device['vendor'] = vendor

        # Don't forget the last device
        if current_device and 'ip' in current_device:
            devices.append(current_device)

        log(f"nmap found {len(devices)} devices", Colors.GREEN)
    except subprocess.TimeoutExpired:
        log(f"nmap timed out (skipping)", Colors.YELLOW)
    except Exception as e:
        log(f"nmap failed: {e}", Colors.YELLOW)

    return devices


def auto_detect_network() -> str:
    """Auto-detect network CIDR"""
    try:
        result = subprocess.run(['ip', 'route'], capture_output=True, text=True, timeout=5)
        gateway_match = re.search(r'default via (\d+\.\d+\.\d+\.\d+)', result.stdout)
        if gateway_match:
            gateway = gateway_match.group(1)
            network = '.'.join(gateway.split('.')[:3]) + '.0/24'
            log(f"Auto-detected network: {network}", Colors.GREEN)
            return network
    except:
        pass

    return "192.168.1.0/24"


def perform_scan() -> List[Dict]:
    """Perform full network scan"""
    log("Starting network scan", Colors.BLUE)
    start_time = time.time()

    # Load previous state for hostname caching
    state = load_state()

    # Combine results from both scanners
    all_devices = {}

    # Try arp-scan first (faster and more reliable for local network)
    arp_devices = scan_arp()
    for device in arp_devices:
        key = device['mac'] or device['ip']
        all_devices[key] = device

    # Only run nmap if arp-scan found fewer than 5 devices or to fill in missing MACs
    # This saves time on subsequent scans
    if len(arp_devices) < 5 or any(not d.get('mac') for d in arp_devices):
        log("Running nmap to fill in gaps...", Colors.BLUE)
        for device in scan_nmap():
            key = device.get('mac') or device['ip']
            if key not in all_devices:
                all_devices[key] = device
            elif not all_devices[key].get('mac') and device.get('mac'):
                # Update with MAC if we didn't have one
                all_devices[key].update(device)
    else:
        log("Skipping nmap (arp-scan found sufficient devices)", Colors.BLUE)

    # Get port list if port scanning is enabled
    ports_to_scan = []
    if ENABLE_PORT_SCAN:
        ports_to_scan = get_port_list()
        log(f"Port scanning enabled for {len(ports_to_scan)} ports: {ports_to_scan[:10]}{'...' if len(ports_to_scan) > 10 else ''}",
            Colors.BLUE)

    # Resolve hostnames, scan ports, and detect device types
    devices = []
    for device in all_devices.values():
        ip = device['ip']
        mac = device.get('mac', '')
        vendor = device.get('vendor', '') or lookup_vendor(mac)

        # Get hostname
        hostname = device.get('hostname', '')
        if not hostname or hostname == ip:
            hostname = resolve_hostname(ip, state)

        # Scan ports if enabled
        open_ports = []
        if ENABLE_PORT_SCAN and ports_to_scan:
            open_ports = scan_ports(ip, ports_to_scan)

        # Detect device type (now with port information)
        device_type = detect_device_type(hostname, vendor, open_ports)

        # Add local MAC if missing
        if not mac:
            mac = get_local_mac(ip) or ''
            if mac:
                vendor = lookup_vendor(mac)

        devices.append({
            'ip': ip,
            'hostname': hostname,
            'mac': mac,
            'vendor': vendor,  # Can be empty string
            'type': device_type,
            'ports': open_ports  # Store open ports
        })

    # Sort by IP
    devices.sort(key=lambda d: [int(x) for x in d['ip'].split('.')])

    duration = time.time() - start_time
    log(f"Scan completed in {duration:.1f} seconds - found {len(devices)} devices", Colors.YELLOW)

    return devices


def load_state() -> Dict:
    """Load previous state from file"""
    try:
        if Path(STATE_FILE).exists():
            with open(STATE_FILE, 'r') as f:
                return json.load(f)
    except Exception as e:
        log(f"Error loading state: {e}", Colors.RED)

    return {}


def save_state(state: Dict):
    """Save state to file"""
    try:
        with open(STATE_FILE, 'w') as f:
            json.dump(state, f, indent=2)
    except Exception as e:
        log(f"Error saving state: {e}", Colors.RED)


def send_to_trmnl(devices: List[Dict]):
    """Send device data to TRMNL webhook"""
    if not PLUGIN_UUID:
        return

    current_timestamp = int(time.time())
    cutoff = current_timestamp - (OFFLINE_RETENTION * 60)  # Convert minutes to seconds

    # Load previous state
    state = load_state()

    log(f"Old state has {len(state)} devices", Colors.BLUE)
    if state:
        log("=" * 60, Colors.BLUE)
        log("FULL OLD STATE JSON:", Colors.BLUE)
        log(json.dumps(state, indent=2), Colors.BLUE)
        log("=" * 60, Colors.BLUE)

    # Build current map
    current_map = {}
    devices_list = []

    # Add current devices
    for device in devices:
        identifier = device['mac'] or device['ip']

        # Clean vendor: remove "Unknown" and empty it
        vendor = device['vendor']
        if vendor and 'unknown' in vendor.lower():
            vendor = ''

        # Don't send hostname if same as IP (save bytes)
        hostname = device['hostname'] if device['hostname'] != device['ip'] else ''

        # Format ports as comma-separated string (e.g., "22,80,443")
        ports_str = ','.join(str(p) for p in device.get('ports', [])) if device.get('ports') else ''

        device_str = f"{device['ip']}|{hostname}|{device['mac']}|{vendor}|{device['type']}|{current_timestamp}|{ports_str}"
        devices_list.append(device_str)

        current_map[identifier] = {
            'last_seen': current_timestamp,
            'ip': device['ip'],
            'hostname': device['hostname'],
            'mac': device['mac'],
            'vendor': vendor,
            'type': device['type'],
            'ports': device.get('ports', [])
        }

    offline_devices = []

    for identifier, data in state.items():
        last_seen = data.get('last_seen', 0)

        if identifier not in current_map and last_seen > cutoff:
            hostname = data.get('hostname', '')
            if hostname == data.get('ip'):
                hostname = ''

            # Clean vendor from old state too
            vendor = data.get('vendor', '')
            if vendor and 'unknown' in vendor.lower():
                vendor = ''

            # Store device data in a tuple for sorting
            offline_devices.append((
                last_seen,  # First element for sorting
                data.get('ip'),
                hostname,
                data.get('mac'),
                vendor,
                data.get('type', ''),
                data.get('ports', []),
                identifier,
                data  # Keep the full data for logging
            ))

    # Sort by last_seen descending (most recent first)
    offline_devices.sort(key=lambda x: x[0], reverse=True)

    # Now process sorted devices
    offline_count = len(offline_devices)
    for last_seen, ip, hostname, mac, vendor, device_type, ports, identifier, data in offline_devices:
        # Don't send ports for offline devices (they may not be accurate when device comes back online)
        device_str = f"{ip}|{hostname}|{mac}|{vendor}|{device_type}|{last_seen}|"
        devices_list.append(device_str)

        age_minutes = (current_timestamp - last_seen) // 60
        log(f"  Adding offline device: {ip} ({data.get('hostname')}) - last seen {age_minutes}m ago (timestamp: {last_seen})",
            Colors.YELLOW)

    log(f"Added {offline_count} offline devices from state", Colors.YELLOW if offline_count > 0 else Colors.BLUE)

    # Save current state - MERGE with old state to preserve offline devices
    log(f"Merging current scan ({len(current_map)} devices) with old state ({len(state)} devices)", Colors.BLUE)

    # Start with old state
    merged_state = state.copy()

    # Update with current devices (this updates last_seen for online devices)
    merged_state.update(current_map)

    # Remove devices older than OFFLINE_RETENTION
    cutoff_time = current_timestamp - (OFFLINE_RETENTION * 60)
    devices_to_remove = []
    for identifier, data in merged_state.items():
        if data.get('last_seen', 0) < cutoff_time:
            devices_to_remove.append(identifier)

    for identifier in devices_to_remove:
        age_hours = (current_timestamp - merged_state[identifier].get('last_seen', 0)) / 3600
        log(f"Removing device {identifier} ({merged_state[identifier].get('ip')}) - last seen {age_hours:.1f}h ago (> {OFFLINE_RETENTION}m retention)",
            Colors.RED)
        del merged_state[identifier]

    log(f"Saving merged state with {len(merged_state)} total devices", Colors.GREEN)
    save_state(merged_state)

    # Get version string with timestamp
    timestamp = int(datetime.now(UTC).timestamp())
    current_version = get_current_version()
    latest_version = get_latest_version()

    # Build version string: current|latest|timestamp
    version_string = f"{current_version}|{latest_version or ''}|{timestamp}"

    if latest_version and latest_version != current_version:
        log(f"⚠ Update available: {current_version} → {latest_version}", Colors.YELLOW)
    elif latest_version:
        log(f"✓ Running latest version: {current_version}", Colors.GREEN)

    # Build payload
    payload = {
        'merge_variables': {
            'devices_list': devices_list,
            'v': version_string
        }
    }

    payload_json = json.dumps(payload)
    payload_size = len(payload_json)

    log(f"Sending to TRMNL... (size: {payload_size} bytes, devices: {len(devices_list)})", Colors.BLUE)

    # Truncate if too large
    if payload_size > BYTE_LIMIT:
        log(f"Payload exceeds limit ({payload_size} > {BYTE_LIMIT}), truncating...", Colors.YELLOW)

        # Separate online (in current scan) and offline (from previous scans)
        online = [d for d in devices_list if int(d.split('|')[5]) >= timestamp]
        offline = [d for d in devices_list if int(d.split('|')[5]) < timestamp]

        log(f"Online devices: {len(online)}, Offline devices: {len(offline)}", Colors.YELLOW)

        # Add devices until we hit limit
        truncated = []
        for device_str in online + offline:
            test_payload = json.dumps({
                'merge_variables': {
                    'devices_list': truncated + [device_str],
                    'v': version_string
                }
            })

            if len(test_payload) < BYTE_LIMIT - 100:
                truncated.append(device_str)
            else:
                break

        payload = {
            'merge_variables': {
                'devices_list': truncated,
                'v': version_string,
                'truncated': True
            }
        }
        payload_json = json.dumps(payload)
        log(f"Truncated to {len(truncated)} devices ({len(payload_json)} bytes)", Colors.YELLOW)

    # Log FULL payload
    log("=" * 60, Colors.GREEN)
    log("FULL PAYLOAD JSON:", Colors.GREEN)
    log(json.dumps(payload, indent=2), Colors.GREEN)
    log("=" * 60, Colors.GREEN)

    # Send to webhook
    try:
        webhook_url = f"https://trmnl.com/api/custom_plugins/{PLUGIN_UUID}"
        response = requests.post(webhook_url, json=payload, timeout=30)

        if response.status_code in [200, 201]:
            log(f"✓ Sent successfully ({len(payload_json)} bytes, {len(devices_list)} devices)", Colors.GREEN)
        elif response.status_code == 429:
            log("⚠ Rate limited (429)", Colors.YELLOW)
        else:
            log(f"✗ Error sending to TRMNL (HTTP {response.status_code})", Colors.RED)
            log(f"Response: {response.text}", Colors.RED)
    except Exception as e:
        log(f"Error sending to TRMNL: {e}", Colors.RED)


def main():
    current_version = get_current_version()

    print(f"{Colors.BLUE}========================================{Colors.NC}")
    print(f"{Colors.BLUE} Network Scanner with TRMNL{Colors.NC}")
    print(f"{Colors.BLUE} Version: {current_version}{Colors.NC}")
    print(f"{Colors.BLUE}========================================{Colors.NC}")
    print()

    # Download vendor database
    download_vendor_db()

    # Check for updates
    latest_version = get_latest_version()
    if latest_version:
        if latest_version != current_version:
            log(f"⚠ Update available: {current_version} → {latest_version}", Colors.YELLOW)
        else:
            log(f"✓ Running latest version: {current_version}", Colors.GREEN)

    if PLUGIN_UUID:
        log("TRMNL mode ENABLED", Colors.GREEN)
        log(f"Scan interval: {INTERVAL} minutes", Colors.GREEN)
    else:
        log("TRMNL mode DISABLED (single scan)", Colors.YELLOW)

    if ENABLE_PORT_SCAN:
        ports = get_port_list()
        log(f"Port scanning ENABLED ({len(ports)} ports)", Colors.GREEN)
        if len(ports) <= 20:
            log(f"Ports: {', '.join(str(p) for p in ports)}", Colors.GREEN)
    else:
        log("Port scanning DISABLED", Colors.YELLOW)

    scan_count = 0

    while True:
        scan_count += 1
        log(f"--- Scan #{scan_count} ---", Colors.BLUE)

        devices = perform_scan()

        # Print results
        for device in devices:
            ports_display = f" [Ports: {','.join(str(p) for p in device['ports'])}]" if device.get('ports') else ""
            print(
                f" • {device['hostname']} ({device['ip']}) - {device['mac']} [{device['vendor']}] - {device['type']}{ports_display}")

        if not PLUGIN_UUID:
            log("Single scan complete.", Colors.GREEN)
            break

        send_to_trmnl(devices)

        sleep_seconds = INTERVAL * 60
        log(f"Sleeping for {INTERVAL} minutes...", Colors.BLUE)
        time.sleep(sleep_seconds)


if __name__ == "__main__":
    main()