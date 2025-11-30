#!/bin/bash

echo "Starting UNIVERSAL network scanner..."

PLUGIN_UUID="${PLUGIN_UUID:-unknown}"
INTERVAL_MINUTES="${INTERVAL:-1}"
INTERVAL=$((INTERVAL_MINUTES * 60))

BYTE_LIMIT="${BYTE_LIMIT:-50000}"

timestamp() { date '+%Y-%m-%d %H:%M:%S'; }

# -----------------------------
# Detect correct interface & subnet
# -----------------------------
detect_subnet() {
    iface=$(ip route show default | awk '{print $5}' | head -n1)

    ip_addr=$(ip -o -f inet addr show "$iface" | awk '{print $4}')
    echo "$ip_addr"
}

# -----------------------------
# ARP table reader
# -----------------------------
read_arp() {
    if [ -f /host/arp ]; then
        grep -E "([0-9]{1,3}\.){3}[0-9]{1,3}" /host/arp \
        | awk '{print $1","$4}'
    fi
}

# -----------------------------
# Direct ARP scan (most accurate)
# -----------------------------
arp_sweep() {
    arp-scan --interface="$iface" --localnet 2>/dev/null \
        | awk '/[0-9a-f]{2}:/ {print $1","$2}'
}

# -----------------------------
# Nmap ping fallback
# -----------------------------
nmap_ping() {
    nmap -sn "$SUBNET" 2>/dev/null \
        | grep "Nmap scan report" \
        | awk '{print $5",alive"}'
}

# -----------------------------
# Send to TRMNL
# -----------------------------
send_to_trmnl() {
    curl -s -X POST "https://plugin.trmnl.me/$PLUGIN_UUID" \
        -H "Content-Type: application/json" \
        --data "$1" >/dev/null
}

# -----------------------------
# MAIN LOOP
# -----------------------------
while true; do
    SUBNET=$(detect_subnet)
    iface=$(ip route show default | awk '{print $5}' | head -n1)

    echo "[`timestamp`] Scanning network: $SUBNET on $iface"

    declare -A devices

    # 1. ARP sweep
    while IFS=',' read -r ip mac; do
        [ -z "$ip" ] && continue
        devices["$ip"]="$mac"
    done < <(arp_sweep)

    # 2. Host ARP table
    while IFS=',' read -r ip mac; do
        [ -z "$ip" ] && continue
        devices["$ip"]="$mac"
    done < <(read_arp)

    # 3. nmap fallback
    while IFS=',' read -r ip alive; do
        [ -z "$ip" ] && continue
        devices["$ip"]="${devices[$ip]}"
    done < <(nmap_ping)

    echo "Devices detected:"

    # JSON output
    json="{\"devices\":["
    first=true

    for ip in "${!devices[@]}"; do
        mac="${devices[$ip]}"
        echo " • $ip  MAC:$mac"

        [ "$first" = true ] || json+=","
        first=false

        json+="{\"ip\":\"$ip\",\"mac\":\"$mac\"}"
    done

    json+="]}"

    send_to_trmnl "$json"
    echo "[`timestamp`] Sent updated device list to TRMNL"

    sleep "$INTERVAL"
done
