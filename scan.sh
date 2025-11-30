#!/bin/bash

echo "Starting UNIVERSAL network scanner..."

INTERVAL="${INTERVAL:-60}"
PLUGIN_UUID="${PLUGIN_UUID:-unknown}"
BYTE_LIMIT="${BYTE_LIMIT:-50000}"

# -----------------------------
# Discover local network subnet
# -----------------------------
get_subnet() {
    ip route | awk '/src/ {print $1; exit}'
}

# -----------------------------
# Parse ARP table from host
# -----------------------------
read_arp_table() {
    if [ -f /host/arp ]; then
        cat /host/arp | tail -n +2 | awk '{print $1","$3}'
    fi
}

# -----------------------------
# DHCP lease discovery
# -----------------------------
read_dhcp_leases() {
    for f in /host/dhcp/*.leases /host/dhcp2/*.leases; do
        [ -f "$f" ] || continue
        awk '{print $3","$2}' "$f"
    done
}

# -----------------------------
# ICMP ping sweep
# -----------------------------
ping_sweep() {
    nmap -sn "$SUBNET" -oG - | awk '/Up$/{print $2",nmap"}'
}

# -----------------------------
# Merge & output devices
# -----------------------------
send_to_trmnl() {
    local json="$1"
    curl -s -X POST "https://plugin.trmnl.me/$PLUGIN_UUID" \
        -H "Content-Type: application/json" \
        --data "$json" >/dev/null
}

# -----------------------------
# Main loop
# -----------------------------
while true; do
    SUBNET="$(get_subnet)"
    echo "[`date '+%Y-%m-%d %H:%M:%S'`] Scanning network: $SUBNET"

    declare -A devices

    # ARP table
    while IFS=',' read -r ip mac; do
        [ -z "$ip" ] && continue
        devices["$ip,mac"]="$mac"
    done < <(read_arp_table)

    # DHCP leases
    while IFS=',' read -r ip mac; do
        [ -z "$ip" ] && continue
        devices["$ip,dhcp"]="$mac"
    done < <(read_dhcp_leases)

    # Nmap ping sweep
    while IFS=',' read -r ip src; do
        [ -z "$ip" ] && continue
        devices["$ip,ping"]="alive"
    done < <(ping_sweep)

    echo "Devices detected:"
    json="{\"devices\":["
    first=true

    for key in "${!devices[@]}"; do
        ip="${key%%,*}"
        info="${devices[$key]}"

        echo " • $ip  MAC:$info"

        [ "$first" = true ] || json+=","
        first=false
        json+="{\"ip\":\"$ip\",\"mac\":\"$info\"}"
    done

    json+="]}"

    send_to_trmnl "$json"
    echo "[`date '+%Y-%m-%d %H:%M:%S'`] Sent updated device list to TRMNL"

    sleep "$INTERVAL"
done
