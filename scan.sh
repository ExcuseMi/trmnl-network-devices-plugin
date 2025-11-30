#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# Vendor DB URL
VENDOR_DB_URL="https://raw.githubusercontent.com/trezor/trezor-firmware/master/common/vendor_db.txt"
VENDOR_DB="/tmp/device-vendors.txt"

log() {
    echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >&2
}

# ----------------------------
# Download vendor DB automatically
# ----------------------------
if [ ! -f "$VENDOR_DB" ]; then
    log "${YELLOW}Downloading vendor database...${NC}"
    curl -s -o "$VENDOR_DB" "$VENDOR_DB_URL" || touch "$VENDOR_DB"
fi

lookup_vendor() {
    local mac="$1"
    [ -z "$mac" ] && echo "Unknown" && return
    local oui=$(echo "$mac" | awk -F: '{print toupper($1$2$3)}')
    grep -i "$oui" "$VENDOR_DB" | awk -F'\t' '{print $2}' | head -n1 || echo "Unknown"
}

resolve_hostname() {
    local IP="$1"
    hostname=$(getent hosts "$IP" | awk '{print $2}')
    [ -z "$hostname" ] && hostname="$IP"
    echo "$hostname"
}

# ----------------------------
# Perform full scan
# ----------------------------
perform_scan() {
    local NETWORK="$1"
    log "${BLUE}Starting network scan on $NETWORK${NC}"

    SCAN_START=$(date +%s)
    TEMP_FILE=$(mktemp)
    echo "[]" > "$TEMP_FILE"

    # ----------------------------
    # 1️⃣ ARP-scan
    # ----------------------------
    if command -v arp-scan >/dev/null 2>&1; then
        INTERFACE=$(ip route | awk '/default/ {print $5}')
        ARP_OUTPUT=$(sudo arp-scan --interface="$INTERFACE" "$NETWORK" 2>/dev/null || true)

        while read -r ip mac vendor; do
            [ -z "$ip" ] && continue
            hostname=$(resolve_hostname "$ip")
            [ -z "$vendor" ] && vendor=$(lookup_vendor "$mac")

            jq --arg ip "$ip" \
               --arg hostname "$hostname" \
               --arg mac "$mac" \
               --arg vendor "$vendor" \
               '. += [{"ip": $ip, "hostname": $hostname, "mac": $mac, "vendor": $vendor}]' \
               "$TEMP_FILE" > "$TEMP_FILE.tmp" && mv "$TEMP_FILE.tmp" "$TEMP_FILE"
        done <<< "$(echo "$ARP_OUTPUT" | awk '/([0-9]{1,3}\.){3}[0-9]{1,3}/ {print $1, $2, $3}')"
    else
        log "${YELLOW}arp-scan not found, skipping layer-2 scan${NC}"
    fi

    # ----------------------------
    # 2️⃣ Nmap fallback
    # ----------------------------
    NMAP_OUTPUT=$(nmap -sn -T4 --max-retries 1 "$NETWORK" 2>/dev/null)

    CURRENT_IP=""
    CURRENT_HOSTNAME=""

    while IFS= read -r line; do
        if [[ $line == *"Nmap scan report"* ]]; then
            IP=$(echo "$line" | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b")

            EXISTS=$(jq --arg ip "$IP" 'map(.ip==$ip) | any' "$TEMP_FILE")
            [ "$EXISTS" = "true" ] && continue

            CURRENT_IP="$IP"
            CURRENT_HOSTNAME=$(echo "$line" | sed -n 's/Nmap scan report for \(.*\)/\1/p')
            [ -z "$CURRENT_HOSTNAME" ] && CURRENT_HOSTNAME="$CURRENT_IP"

        elif [[ $line == *"MAC Address"* ]] && [ -n "$CURRENT_IP" ]; then
            MAC=$(echo "$line" | awk '{print $3}')
            VENDOR=$(echo "$line" | cut -d'(' -f2 | cut -d')' -f1)
            [ -z "$VENDOR" ] && VENDOR=$(lookup_vendor "$MAC")

            jq --arg ip "$CURRENT_IP" \
               --arg hostname "$CURRENT_HOSTNAME" \
               --arg mac "$MAC" \
               --arg vendor "$VENDOR" \
               '. += [{"ip": $ip, "hostname": $hostname, "mac": $mac, "vendor": $vendor}]' \
               "$TEMP_FILE" > "$TEMP_FILE.tmp" && mv "$TEMP_FILE.tmp" "$TEMP_FILE"

            CURRENT_IP=""
            CURRENT_HOSTNAME=""
        fi
    done <<< "$NMAP_OUTPUT"

    SCAN_END=$(date +%s)
    SCAN_DURATION=$((SCAN_END - SCAN_START))
    log "${YELLOW}Scan took $SCAN_DURATION seconds${NC}"

    # Sort by numeric IP
    jq 'sort_by(.ip | split(".") | map(tonumber))' "$TEMP_FILE"
    rm "$TEMP_FILE"
}

# ----------------------------
# Send data to TRMNL
# ----------------------------
send_to_trmnl() {
    local DEVICES="$1"
    local PLUGIN_UUID="$2"

    BYTE_LIMIT=${BYTE_LIMIT:-2000}
    STATE_FILE="/tmp/network_scanner_state.json"
    CURRENT_TIMESTAMP=$(date +%s)

    CURRENT_MAP='{}'
    DEVICES_ARRAY='[]'

    # Build current list
    while IFS= read -r device; do
        IP=$(echo "$device" | jq -r '.ip')
        HOSTNAME=$(echo "$device" | jq -r '.hostname')
        MAC=$(echo "$device" | jq -r '.mac')
        VENDOR=$(echo "$device" | jq -r '.vendor')

        IDENTIFIER="${MAC:-$IP}"

        DEVICE_STR="$IP|$HOSTNAME|$MAC|$VENDOR|1"
        DEVICES_ARRAY=$(echo "$DEVICES_ARRAY" | jq --arg d "$DEVICE_STR" '. += [$d]')

        CURRENT_MAP=$(echo "$CURRENT_MAP" | jq --arg id "$IDENTIFIER" \
            --arg ts "$CURRENT_TIMESTAMP" \
            --arg ip "$IP" --arg hostname "$HOSTNAME" \
            --arg mac "$MAC" --arg vendor "$VENDOR" \
            '. + {($id): {last_seen: $ts, ip: $ip, hostname: $hostname, mac: $mac, vendor: $vendor}}')

    done < <(echo "$DEVICES" | jq -c '.[]')

    # Merge offline devices
    if [ -f "$STATE_FILE" ]; then
        PREV=$(cat "$STATE_FILE")
        CUTOFF=$((CURRENT_TIMESTAMP - 86400)) # 24h

        echo "$PREV" | jq -r 'to_entries | .[] | @json' | while read -r entry; do
            ID=$(echo "$entry" | jq -r '.key')
            TS=$(echo "$entry" | jq -r '.value.last_seen')

            IN_CURRENT=$(echo "$CURRENT_MAP" | jq --arg id "$ID" 'has($id)')
            if [ "$IN_CURRENT" = "false" ] && [ "$TS" -gt "$CUTOFF" ]; then
                P_IP=$(echo "$entry" | jq -r '.value.ip')
                P_HN=$(echo "$entry" | jq -r '.value.hostname')
                P_MAC=$(echo "$entry" | jq -r '.value.mac')
                P_VEND=$(echo "$entry" | jq -r '.value.vendor')

                DEVICE_STR="$P_IP|$P_HN|$P_MAC|$P_VEND|0"
                DEVICES_ARRAY=$(echo "$DEVICES_ARRAY" | jq --arg d "$DEVICE_STR" '. += [$d]')
            fi
        done
    fi

    echo "$CURRENT_MAP" > "$STATE_FILE"

    TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

    PAYLOAD=$(jq -n \
        --argjson devices "$DEVICES_ARRAY" \
        --arg timestamp "$TIMESTAMP" \
        '{ merge_variables: { devices_list: $devices, last_scan: $timestamp }}')

    WEBHOOK_URL="https://usetrmnl.com/api/custom_plugins/$PLUGIN_UUID"

    log "${BLUE}Sending to TRMNL...${NC}"
    RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$WEBHOOK_URL" \
        -H "Content-Type: application/json" \
        -d "$PAYLOAD")

    HTTP_CODE=$(echo "$RESPONSE" | tail -n1)

    if [[ "$HTTP_CODE" == 200 || "$HTTP_CODE" == 201 ]]; then
        log "${GREEN}✓ Sent successfully${NC}"
    elif [[ "$HTTP_CODE" == 429 ]]; then
        log "${YELLOW}⚠ Rate limited (429)${NC}"
    else
        log "${RED}✗ Error sending to TRMNL (HTTP $HTTP_CODE)${NC}"
    fi
}

# ----------------------------
# Main script
# ----------------------------
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE} Network Scanner with TRMNL${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

if [ -n "$PLUGIN_UUID" ]; then
    log "${GREEN}TRMNL mode ENABLED${NC}"
    INTERVAL=${INTERVAL:-15}
else
    log "${YELLOW}TRMNL mode DISABLED (single scan)${NC}"
fi

# Auto-detect CIDR if not set
if [ -z "$NETWORK" ]; then
    GATEWAY=$(ip route | grep default | awk '{print $3}')
    NETWORK=$(echo "$GATEWAY" | cut -d'.' -f1-3).0/24
    log "${GREEN}Auto-detected network: $NETWORK${NC}"
else
    log "${GREEN}Using network: $NETWORK${NC}"
fi
echo ""

SCAN_COUNT=0
while true; do
    SCAN_COUNT=$((SCAN_COUNT+1))
    log "${BLUE}--- Scan #$SCAN_COUNT ---${NC}"

    DEVICES=$(perform_scan "$NETWORK")

    echo "$DEVICES" | jq -r \
        '.[] | " • \(.hostname) (\(.ip)) - \(.mac) [\(.vendor)]"'

    if [ -z "$PLUGIN_UUID" ]; then
        log "${GREEN}Single scan complete.${NC}"
        break
    fi

    send_to_trmnl "$DEVICES" "$PLUGIN_UUID"

    SLEEP_SECONDS=$((INTERVAL * 60))
    log "${BLUE}Sleeping for $INTERVAL minutes...${NC}"
    sleep $SLEEP_SECONDS
done
