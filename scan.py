#!/usr/bin/env python3

import os
import sys
import json
import time
import subprocess
import re
import socket
import requests
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Configuration
VENDOR_DB_URL = "https://www.wireshark.org/download/automated/data/manuf"
VENDOR_DB_PATH = "/tmp/device-vendors.txt"
STATE_FILE = "/tmp/network_scanner_state.json"
BYTE_LIMIT = int(os.getenv("BYTE_LIMIT", "2000"))
PLUGIN_UUID = os.getenv("PLUGIN_UUID", "")
INTERVAL = int(os.getenv("INTERVAL", "15"))
NETWORK = os.getenv("NETWORK", "")


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


def lookup_vendor(mac: str) -> str:
    """Look up vendor by MAC address OUI"""
    if not mac:
        return "Unknown"

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
                    return parts[2] if len(parts) >= 3 else parts[1]

        return "Unknown"
    except Exception as e:
        log(f"Error looking up vendor for {mac}: {e}", Colors.RED)
        return "Unknown"


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


def detect_device_type(hostname: str, vendor: str) -> str:
    """Detect device type based on hostname and vendor"""
    h = hostname.lower()
    v = vendor.lower()

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

    # Mobile
    if any(x in h for x in ['phone', 'mobile', 'tablet', 'ipad']):
        return "Mobile Device"

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

    return "Network Device"


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
                    'vendor': vendor if vendor else "Unknown"
                })

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

        result = subprocess.run(['nmap', '-sn', '-R', '--system-dns', '-T4',
                                 '--max-retries', '1', network],
                                capture_output=True, text=True, timeout=120)

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
    for device in scan_arp():
        key = device['mac'] or device['ip']
        all_devices[key] = device

    # Fill in gaps with nmap
    for device in scan_nmap():
        key = device.get('mac') or device['ip']
        if key not in all_devices:
            all_devices[key] = device
        elif not all_devices[key].get('mac') and device.get('mac'):
            # Update with MAC if we didn't have one
            all_devices[key].update(device)

    # Resolve hostnames and detect device types
    devices = []
    for device in all_devices.values():
        ip = device['ip']
        mac = device.get('mac', '')
        vendor = device.get('vendor', '') or lookup_vendor(mac)

        # Get hostname
        hostname = device.get('hostname', '')
        if not hostname or hostname == ip:
            hostname = resolve_hostname(ip, state)

        # Detect device type
        device_type = detect_device_type(hostname, vendor)

        # Add local MAC if missing
        if not mac:
            mac = get_local_mac(ip) or ''
            if mac:
                vendor = lookup_vendor(mac)

        devices.append({
            'ip': ip,
            'hostname': hostname,
            'mac': mac,
            'vendor': vendor or 'Unknown',
            'type': device_type
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
    cutoff = current_timestamp - 86400  # 24 hours

    # Load previous state
    state = load_state()

    # Build current map
    current_map = {}
    devices_list = []

    # Add current devices
    for device in devices:
        identifier = device['mac'] or device['ip']

        # Don't send hostname if same as IP (save bytes)
        hostname = device['hostname'] if device['hostname'] != device['ip'] else ''

        device_str = f"{device['ip']}|{hostname}|{device['mac']}|{device['vendor']}|{device['type']}|{current_timestamp}"
        devices_list.append(device_str)

        current_map[identifier] = {
            'last_seen': current_timestamp,
            'ip': device['ip'],
            'hostname': device['hostname'],
            'mac': device['mac'],
            'vendor': device['vendor'],
            'type': device['type']
        }

    # Add offline devices (seen in last 24h)
    for identifier, data in state.items():
        last_seen = data.get('last_seen', 0)

        if identifier not in current_map and last_seen > cutoff:
            hostname = data.get('hostname', '')
            if hostname == data.get('ip'):
                hostname = ''

            device_str = f"{data.get('ip')}|{hostname}|{data.get('mac')}|{data.get('vendor')}|{data.get('type', 'Network Device')}|{last_seen}"
            devices_list.append(device_str)

    # Save current state
    save_state(current_map)

    # Build payload
    timestamp = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
    payload = {
        'merge_variables': {
            'devices_list': devices_list,
            'last_scan': timestamp
        }
    }

    payload_json = json.dumps(payload)
    payload_size = len(payload_json)

    log(f"Sending to TRMNL... (size: {payload_size} bytes, devices: {len(devices_list)})", Colors.BLUE)

    # Truncate if too large
    if payload_size > BYTE_LIMIT:
        log(f"Payload exceeds limit ({payload_size} > {BYTE_LIMIT}), truncating...", Colors.YELLOW)

        # Separate online and offline
        online = [d for d in devices_list if int(d.split('|')[-1]) >= current_timestamp - 600]
        offline = [d for d in devices_list if int(d.split('|')[-1]) < current_timestamp - 600]

        # Add devices until we hit limit
        truncated = []
        for device_str in online + offline:
            test_payload = json.dumps({
                'merge_variables': {
                    'devices_list': truncated + [device_str],
                    'last_scan': timestamp
                }
            })

            if len(test_payload) < BYTE_LIMIT - 100:
                truncated.append(device_str)
            else:
                break

        payload = {
            'merge_variables': {
                'devices_list': truncated,
                'last_scan': timestamp,
                'truncated': True
            }
        }
        payload_json = json.dumps(payload)
        log(f"Truncated to {len(truncated)} devices ({len(payload_json)} bytes)", Colors.YELLOW)

    # Send to webhook
    try:
        webhook_url = f"https://usetrmnl.com/api/custom_plugins/{PLUGIN_UUID}"
        response = requests.post(webhook_url, json=payload, timeout=30)

        if response.status_code in [200, 201]:
            log(f"✓ Sent successfully ({len(payload_json)} bytes, {len(devices_list)} devices)", Colors.GREEN)
        elif response.status_code == 429:
            log("⚠ Rate limited (429)", Colors.YELLOW)
        else:
            log(f"✗ Error sending to TRMNL (HTTP {response.status_code})", Colors.RED)
    except Exception as e:
        log(f"Error sending to TRMNL: {e}", Colors.RED)


def main():
    print(f"{Colors.BLUE}========================================{Colors.NC}")
    print(f"{Colors.BLUE} Network Scanner with TRMNL{Colors.NC}")
    print(f"{Colors.BLUE}========================================{Colors.NC}")
    print()

    # Download vendor database
    download_vendor_db()

    if PLUGIN_UUID:
        log("TRMNL mode ENABLED", Colors.GREEN)
        log(f"Scan interval: {INTERVAL} minutes", Colors.GREEN)
    else:
        log("TRMNL mode DISABLED (single scan)", Colors.YELLOW)

    scan_count = 0

    while True:
        scan_count += 1
        log(f"--- Scan #{scan_count} ---", Colors.BLUE)

        devices = perform_scan()

        # Print results
        for device in devices:
            print(f" • {device['hostname']} ({device['ip']}) - {device['mac']} [{device['vendor']}] - {device['type']}")

        if not PLUGIN_UUID:
            log("Single scan complete.", Colors.GREEN)
            break

        send_to_trmnl(devices)

        sleep_seconds = INTERVAL * 60
        log(f"Sleeping for {INTERVAL} minutes...", Colors.BLUE)
        time.sleep(sleep_seconds)


if __name__ == "__main__":
    main()