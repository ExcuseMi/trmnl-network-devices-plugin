#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# Paths to local DBs
OUI_DB="/app/oui-db.txt"
DEVICE_DB="/app/device-db.json"

# Function to print with timestamp
log() {
    echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >&2
}

# Lookup vendor/device by MAC prefix
lookup_vendor_device() {
    local MAC="$1"
    local PREFIX=$(echo "$MAC" | awk -F: '{print toupper($1$2$3)}')
    local VENDOR=""
    local DEVICE=""

    # Lookup vendor from OUI_DB
    if [ -f "$OUI_DB" ]; then
        VENDOR=$(grep -i "^$PREFIX" "$OUI_DB" | awk -F'\t' '{print $2}' | head -n1)
    fi

    # Lookup device model from DEVICE_DB
    if [ -f "$DEVICE_DB" ]; then
        DEVICE=$(jq -r --arg p "$PREFIX" '.[$p] // empty' "$DEVICE_DB")
    fi

    echo "$VENDOR|$DEVICE"
}

# Resolve hostname from IP
resolve_hostname() {
    local IP="$1"
    hostname=$(getent hosts "$IP" | awk '{print $2}')
    [ -z "$hostname" ] && hostname="$IP"
    echo "$hostname"
}

# Perform network scan
perform_scan() {
    local NETWORK="$1"
    log "${BLUE}Starting network scan on $NETWORK${NC}"

    SCAN_START=$(date +%s)
    TEMP_FILE=$(mktemp)
    echo "[]" > "$TEMP_FILE"

    # ----------------------------
    # 1️⃣ ARP-scan (requires root)
    # ----------------------------
    if command -v arp-scan >/dev/null 2>&1; then
        ARP_OUTPUT=$(sudo arp-scan --localnet 2>/dev/null || true)
        while read -r ip mac vendor; do
            [ -z "$ip" ] && continue
            [ "$ip" = "Interface:" ] && continue
            hostname=$(resolve_hostname "$ip")

            # Lookup local DB for vendor/device
            DB_RESULT=$(lookup_vendor_device "$mac")
            VENDOR_DB=$(echo "$DB_RESULT" | cut -d'|' -f1)
            DEVICE_DB_NAME=$(echo "$DB_RESULT" | cut -d'|' -f2)
            [ -z "$VENDOR_DB" ] && VENDOR_DB="$vendor"

            TEMP_CONTENT=$(cat "$TEMP_FILE")
            echo "$TEMP_CONTENT" | jq --arg ip "$ip" \
                                      --arg hostname "$hostname" \
                                      --arg mac "$mac" \
                                      --arg vendor "$VENDOR_DB" \
                                      --arg device "$DEVICE_DB_NAME" \
                                      '. += [{"ip": $ip, "hostname": $hostname, "mac": $mac, "vendor": $vendor, "device": $device}]' \
                                      > "$TEMP_FILE"
        done <<< "$(echo "$ARP_OUTPUT" | awk '/([0-9]{1,3}\.){3}[0-9]{1,3}/ {print $1, $2, $3}')"
    else
        log "${YELLOW}arp-scan not found, skipping L2 scan${NC}"
    fi

    # ----------------------------
    # 2️⃣ Fallback: nmap ping scan
    # ----------------------------
    NMAP_OUTPUT=$(nmap -sn -T4 --max-retries 1 "$NETWORK" 2>/dev/null)
    CURRENT_IP=""
    CURRENT_HOSTNAME=""
    while IFS= read -r line; do
        if [[ $line == *"Nmap scan report"* ]]; then
            IP=$(echo "$line" | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b")
            EXISTS=$(cat "$TEMP_FILE" | jq --arg ip "$IP" 'map(.ip==$ip) | any')
            if [ "$EXISTS" = "true" ]; then
                CURRENT_IP=""
                CURRENT_HOSTNAME=""
                continue
            fi

            CURRENT_IP="$IP"
            CURRENT_HOSTNAME=$(echo "$line" | sed -n 's/Nmap scan report for \(.*\)/\1/p')
            [ -z "$CURRENT_HOSTNAME" ] && CURRENT_HOSTNAME="$CURRENT_IP"
        elif [[ $line == *"MAC Address"* ]] && [ ! -z "$CURRENT_IP" ]; then
            MAC=$(echo "$line" | awk '{print $3}')
            VENDOR_NMAP=$(echo "$line" | cut -d'(' -f2 | cut -d')' -f1)

            DB_RESULT=$(lookup_vendor_device "$MAC")
            VENDOR_DB=$(echo "$DB_RESULT" | cut -d'|' -f1)
            DEVICE_DB_NAME=$(echo "$DB_RESULT" | cut -d'|' -f2)
            [ -z "$VENDOR_DB" ] && VENDOR_DB="$VENDOR_NMAP"

            TEMP_CONTENT=$(cat "$TEMP_FILE")
            echo "$TEMP_CONTENT" | jq --arg ip "$CURRENT_IP" \
                                      --arg hostname "$CURRENT_HOSTNAME" \
                                      --arg mac "$MAC" \
                                      --arg vendor "$VENDOR_DB" \
                                      --arg device "$DEVICE_DB_NAME" \
                                      '. += [{"ip": $ip, "hostname": $hostname, "mac": $mac, "vendor": $vendor, "device": $device}]' \
                                      > "$TEMP_FILE"
            CURRENT_IP=""
            CURRENT_HOSTNAME=""
        fi
    done <<< "$NMAP_OUTPUT"

    SCAN_END=$(date +%s)
    SCAN_DURATION=$((SCAN_END - SCAN_START))
    log "${YELLOW}Scan took ${SCAN_DURATION} seconds${NC}"

    # Sort by IP
    DEVICES=$(cat "$TEMP_FILE" | jq 'sort_by(.ip)')
    rm "$TEMP_FILE"
    echo "$DEVICES"
}

# send_to_trmnl remains unchanged (preserves previous devices, offline marking, TRMNL JSON)
# ... [Copy your send_to_trmnl function here, unchanged]

# ----------------------------
# Main script
# ----------------------------
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE} Network Scanner with TRMNL${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# TRMNL mode
if [ ! -z "$PLUGIN_UUID" ]; then
    log "${GREEN}TRMNL mode enabled${NC}"
    INTERVAL=${INTERVAL:-15}
    log "${BLUE}Scan interval: $INTERVAL minutes${NC}"
else
    log "${YELLOW}TRMNL mode disabled (single scan)${NC}"
fi

# Auto-detect network
if [ -z "$NETWORK" ]; then
    GATEWAY=$(ip route | grep default | awk '{print $3}')
    NETWORK=$(echo $GATEWAY | cut -d'.' -f1-3).0/24
    log "${GREEN}Auto-detected network: $NETWORK${NC}"
else
    log "${GREEN}Using network: $NETWORK${NC}"
fi
echo ""

# ----------------------------
# Scan loop
# ----------------------------
SCAN_COUNT=0
while true; do
    SCAN_COUNT=$((SCAN_COUNT + 1))
    log "${BLUE}--- Scan #$SCAN_COUNT ---${NC}"

    DEVICES=$(perform_scan "$NETWORK")
    echo "$DEVICES" | jq -r '.[] | " • \(.hostname) (\(.ip))" + (if .mac then " - \(.mac) [\(.vendor)]" else "" end) + (if .device then " {\(.device)}" else "" end)'

    if [ ! -z "$PLUGIN_UUID" ]; then
        send_to_trmnl "$DEVICES" "$PLUGIN_UUID"
    else
        log "${GREEN}Single scan complete!${NC}"
        break
    fi

    SLEEP_SECONDS=$((INTERVAL*60))
    log "${BLUE}Sleeping for $INTERVAL minutes...${NC}"
    sleep $SLEEP_SECONDS
done
