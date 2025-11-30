#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Function to print with timestamp
log() {
    echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >&2
}

# Function to resolve hostname from IP
resolve_hostname() {
    local IP="$1"
    hostname=$(getent hosts "$IP" | awk '{print $2}')
    if [ -z "$hostname" ]; then
        hostname="$IP"
    fi
    echo "$hostname"
}

# Function to perform network scan
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
            TEMP_CONTENT=$(cat "$TEMP_FILE")
            echo "$TEMP_CONTENT" | jq --arg ip "$ip" \
                                      --arg hostname "$hostname" \
                                      --arg mac "$mac" \
                                      --arg vendor "$vendor" \
                                      '. += [{"ip": $ip, "hostname": $hostname, "mac": $mac, "vendor": $vendor}]' \
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
            # Skip if IP already in TEMP_FILE
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
            VENDOR=$(echo "$line" | cut -d'(' -f2 | cut -d')' -f1)
            TEMP_CONTENT=$(cat "$TEMP_FILE")
            echo "$TEMP_CONTENT" | jq --arg ip "$CURRENT_IP" \
                                      --arg hostname "$CURRENT_HOSTNAME" \
                                      --arg mac "$MAC" \
                                      --arg vendor "$VENDOR" \
                                      '. += [{"ip": $ip, "hostname": $hostname, "mac": $mac, "vendor": $vendor}]' \
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

# ----------------------------
# Function to send to TRMNL
# ----------------------------
send_to_trmnl() {
    local DEVICES="$1"
    local PLUGIN_UUID="$2"
    BYTE_LIMIT=${BYTE_LIMIT:-2000}
    STATE_FILE="/tmp/network_scanner_state.json"
    CURRENT_TIMESTAMP=$(date +%s)
    CURRENT_MAP='{}'

    # Build current device map
    echo "$DEVICES" | jq -r '.[] | "\(.mac // .ip)"' | while read -r id; do
        [ -z "$id" ] && continue
        CURRENT_MAP=$(echo "$CURRENT_MAP" | jq --arg id "$id" --arg ts "$CURRENT_TIMESTAMP" '. + {($id): {last_seen: $ts}}')
    done

    # Build device array for TRMNL
    DEVICES_ARRAY='[]'
    while IFS= read -r device; do
        IP=$(echo "$device" | jq -r '.ip')
        HOSTNAME=$(echo "$device" | jq -r '.hostname // .ip')
        MAC=$(echo "$device" | jq -r '.mac // ""')
        VENDOR=$(echo "$device" | jq -r '.vendor // ""')
        IDENTIFIER="${MAC:-$IP}"
        DEVICE_STR="$IP|$HOSTNAME|$MAC|$VENDOR|1"
        DEVICES_ARRAY=$(echo "$DEVICES_ARRAY" | jq --arg d "$DEVICE_STR" '. += [$d]')
        CURRENT_MAP=$(echo "$CURRENT_MAP" | jq --arg id "$IDENTIFIER" --arg ts "$CURRENT_TIMESTAMP" \
            --arg ip "$IP" --arg hostname "$HOSTNAME" --arg mac "$MAC" --arg vendor "$VENDOR" \
            '. + {($id): {last_seen: $ts, ip: $ip, hostname: $hostname, mac: $mac, vendor: $vendor}}')
    done < <(echo "$DEVICES" | jq -c '.[]')

    # Merge previous offline devices
    if [ -f "$STATE_FILE" ]; then
        PREVIOUS_DEVICES=$(cat "$STATE_FILE")
        CUTOFF=$((CURRENT_TIMESTAMP - 86400))
        echo "$PREVIOUS_DEVICES" | jq -r 'to_entries | .[] | @json' | while read -r entry; do
            PREV_ID=$(echo "$entry" | jq -r '.key')
            PREV_DATA=$(echo "$entry" | jq -r '.value')
            PREV_TS=$(echo "$PREV_DATA" | jq -r '.last_seen')
            IS_CURRENT=$(echo "$CURRENT_MAP" | jq --arg id "$PREV_ID" 'has($id)')
            if [ "$IS_CURRENT" = "false" ] && [ "$PREV_TS" -gt "$CUTOFF" ]; then
                PREV_IP=$(echo "$PREV_DATA" | jq -r '.ip // ""')
                PREV_HOSTNAME=$(echo "$PREV_DATA" | jq -r '.hostname // ""')
                PREV_MAC=$(echo "$PREV_DATA" | jq -r '.mac // ""')
                PREV_VENDOR=$(echo "$PREV_DATA" | jq -r '.vendor // ""')
                [ -z "$PREV_IP" ] && continue
                DEVICE_STR="$PREV_IP|$PREV_HOSTNAME|$PREV_MAC|$PREV_VENDOR|0"
                DEVICES_ARRAY=$(echo "$DEVICES_ARRAY" | jq --arg d "$DEVICE_STR" '. += [$d]')
            fi
        done
    fi

    echo "$CURRENT_MAP" > "$STATE_FILE"
    TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

    PAYLOAD=$(jq -n --argjson devices "$DEVICES_ARRAY" --arg timestamp "$TIMESTAMP" \
        '{ merge_variables: { devices_list: $devices, last_scan: $timestamp } }')

    PAYLOAD_SIZE=${#PAYLOAD}
    WEBHOOK_URL="https://usetrmnl.com/api/custom_plugins/$PLUGIN_UUID"
    log "${BLUE}Sending data to TRMNL...${NC}"
    RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$WEBHOOK_URL" \
        -H "Content-Type: application/json" -d "$PAYLOAD")
    HTTP_CODE=$(echo "$RESPONSE" | tail -n1)

    if [[ "$HTTP_CODE" =~ ^(200|201)$ ]]; then
        log "${GREEN}✓ Successfully sent to TRMNL${NC}"
    elif [ "$HTTP_CODE" = "429" ]; then
        log "${YELLOW}⚠ Rate limited by TRMNL (429)${NC}"
    else
        log "${RED}✗ Failed to send to TRMNL (HTTP $HTTP_CODE)${NC}"
    fi
}

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
    if [ -z "$GATEWAY" ]; then
        log "${RED}Could not detect network automatically.${NC}"
        exit 1
    fi
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
    echo "$DEVICES" | jq -r '.[] | " • \(.hostname) (\(.ip))" + (if .mac then " - \(.mac) [\(.vendor)]" else "" end)'

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
