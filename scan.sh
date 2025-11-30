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

# Get primary network interface
get_interface() {
    ip route | awk '/default/ {print $5; exit}'
}

# Get subnet of interface
get_subnet() {
    iface="$1"
    ip -o -f inet addr show "$iface" | awk '{print $4}'
}

# Reverse DNS lookup
resolve_hostname() {
    host=$(dig +short -x "$1" 2>/dev/null | head -n1 | sed 's/\.$//')
    echo "${host:-$1}"
}

# Skip Docker internal IPs
is_docker_ip() {
    if [[ "$1" =~ ^172\.(1[6-9]|2[0-9]|3[0-1])\. ]]; then
        return 0
    fi
    return 1
}

# Perform ARP scan using nmap
arp_scan() {
    network="$1"
    nmap -sn -T4 --max-retries 1 --host-timeout 20s "$network" 2>/dev/null
}

# Load previous state
STATE_FILE="/tmp/network_scanner_state.json"
if [ -f "$STATE_FILE" ]; then
    PREVIOUS_DEVICES=$(cat "$STATE_FILE")
else
    PREVIOUS_DEVICES='{}'
fi

# Convert INTERVAL in minutes to seconds
INTERVAL=${INTERVAL:-15}
SLEEP_SECONDS=$((INTERVAL * 60))

# Determine network
if [ -z "$NETWORK" ]; then
    iface=$(get_interface)
    SUBNET=$(get_subnet "$iface")
    if [ -z "$SUBNET" ]; then
        log "${RED}Could not auto-detect network. Specify NETWORK variable.${NC}"
        exit 1
    fi
    NETWORK="$SUBNET"
fi

log "${GREEN}Network Scanner starting on $NETWORK${NC}"

SCAN_COUNT=0

while true; do
    SCAN_COUNT=$((SCAN_COUNT + 1))
    log "${BLUE}--- Scan #$SCAN_COUNT ---${NC}"

    SCAN_OUTPUT=$(arp_scan "$NETWORK")

    # Extract devices
    declare -A macs
    declare -A hosts
    declare -A vendors
    declare -A ips_seen

    CURRENT_IP=""
    CURRENT_HOSTNAME=""
    CURRENT_MAC=""
    CURRENT_VENDOR=""

    while IFS= read -r line; do
        if [[ $line == *"Nmap scan report"* ]]; then
            # Save previous device if exists
            if [ -n "$CURRENT_IP" ]; then
                ips_seen["$CURRENT_IP"]=1
                hosts["$CURRENT_IP"]="$CURRENT_HOSTNAME"
                macs["$CURRENT_IP"]="${CURRENT_MAC:-unknown}"
                vendors["$CURRENT_IP"]="${CURRENT_VENDOR:-Unknown}"
            fi
            # Extract IP and hostname
            CURRENT_IP=$(echo "$line" | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b")
            CURRENT_HOSTNAME=$(echo "$line" | sed -n 's/Nmap scan report for \(.*\)/\1/p')
            if [ -z "$CURRENT_HOSTNAME" ]; then
                CURRENT_HOSTNAME="$CURRENT_IP"
            fi
            CURRENT_MAC=""
            CURRENT_VENDOR=""
        elif [[ $line == *"MAC Address"* ]]; then
            CURRENT_MAC=$(echo "$line" | awk '{print $3}')
            CURRENT_VENDOR=$(echo "$line" | sed -n 's/.*MAC Address: .* (\(.*\))/\1/p')
        fi
    done <<< "$SCAN_OUTPUT"

    # Save last device
    if [ -n "$CURRENT_IP" ]; then
        ips_seen["$CURRENT_IP"]=1
        hosts["$CURRENT_IP"]="$CURRENT_HOSTNAME"
        macs["$CURRENT_IP"]="${CURRENT_MAC:-unknown}"
        vendors["$CURRENT_IP"]="${CURRENT_VENDOR:-Unknown}"
    fi

    # Exclude Docker bridges and scanner IP
    iface=$(get_interface)
    SELF_IP=$(ip -o -f inet addr show "$iface" | awk '{print $4}' | cut -d'/' -f1)
    SELF_MAC=$(cat /sys/class/net/"$iface"/address)

    DEVICES_ARRAY='[]'

    log "Devices detected:"
    for ip in "${!ips_seen[@]}"; do
        if is_docker_ip "$ip" || [ "$ip" = "$SELF_IP" ]; then
            continue
        fi
        hostname="${hosts[$ip]}"
        mac="${macs[$ip]}"
        vendor="${vendors[$ip]}"

        echo " • $hostname ($ip) - $mac [$vendor]"

        DEVICE_STR="$ip|$hostname|$mac|$vendor|1"
        DEVICES_ARRAY=$(echo "$DEVICES_ARRAY" | jq --arg d "$DEVICE_STR" '. += [$d]')
    done

    # Add previous devices not seen now as offline (24h window)
    CURRENT_TIMESTAMP=$(date +%s)
    CUTOFF=$((CURRENT_TIMESTAMP - 86400))

    if [ "$PREVIOUS_DEVICES" != '{}' ]; then
        echo "$PREVIOUS_DEVICES" | jq -r 'to_entries | .[] | @json' | while IFS= read -r entry; do
            PREV_ID=$(echo "$entry" | jq -r '.key')
            PREV_DATA=$(echo "$entry" | jq -r '.value')
            PREV_TS=$(echo "$PREV_DATA" | jq -r '.last_seen')
            IS_CURRENT=$(echo "$DEVICES_ARRAY" | jq --arg id "$PREV_ID" 'any(.[]; . == $id)')
            if [ "$IS_CURRENT" = "false" ] && [ "$PREV_TS" -gt "$CUTOFF" ]; then
                PREV_IP=$(echo "$PREV_DATA" | jq -r '.ip // ""')
                PREV_HOST=$(echo "$PREV_DATA" | jq -r '.hostname // ""')
                PREV_MAC=$(echo "$PREV_DATA" | jq -r '.mac // ""')
                PREV_VENDOR=$(echo "$PREV_DATA" | jq -r '.vendor // ""')
                if [ -n "$PREV_IP" ]; then
                    DEVICE_STR="$PREV_IP|$PREV_HOST|$PREV_MAC|$PREV_VENDOR|0"
                    DEVICES_ARRAY=$(echo "$DEVICES_ARRAY" | jq --arg d "$DEVICE_STR" '. += [$d]')
                fi
            fi
        done
    fi

    # Save state
    CURRENT_MAP='{}'
    for ip in "${!ips_seen[@]}"; do
        CURRENT_MAP=$(echo "$CURRENT_MAP" | jq --arg ip "$ip" --arg ts "$CURRENT_TIMESTAMP" --arg host "${hosts[$ip]}" --arg mac "${macs[$ip]}" --arg vendor "${vendors[$ip]}" \
            '. + {($ip): {last_seen: ($ts|tonumber), hostname: $host, ip: $ip, mac: $mac, vendor: $vendor}}')
    done
    echo "$CURRENT_MAP" > "$STATE_FILE"

    # Build payload
    TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    PAYLOAD=$(jq -n --argjson devices "$DEVICES_ARRAY" --arg timestamp "$TIMESTAMP" \
        '{ merge_variables: { devices_list: $devices, last_scan: $timestamp } }')

    # Truncate if necessary
    BYTE_LIMIT=${BYTE_LIMIT:-2000}
    if [ "${#PAYLOAD}" -gt "$BYTE_LIMIT" ]; then
        log "${YELLOW}Payload too big, truncating...${NC}"
        # Keep devices one by one until limit
        TRUNCATED_ARRAY='[]'
        for d in $(echo "$DEVICES_ARRAY" | jq -r '.[]'); do
            TEST_ARRAY=$(echo "$TRUNCATED_ARRAY" | jq --arg d "$d" '. += [$d]')
            TEST_PAYLOAD=$(jq -n --argjson devices "$TEST_ARRAY" --arg timestamp "$TIMESTAMP" \
                '{ merge_variables: { devices_list: $devices, last_scan: $timestamp, truncated: true } }')
            if [ ${#TEST_PAYLOAD} -lt $((BYTE_LIMIT - 100)) ]; then
                TRUNCATED_ARRAY="$TEST_ARRAY"
            else
                break
            fi
        done
        PAYLOAD=$(jq -n --argjson devices "$TRUNCATED_ARRAY" --arg timestamp "$TIMESTAMP" \
            '{ merge_variables: { devices_list: $devices, last_scan: $timestamp, truncated: true } }')
    fi

    # Send to TRMNL
    if [ -n "$PLUGIN_UUID" ]; then
        WEBHOOK_URL="https://usetrmnl.com/api/custom_plugins/$PLUGIN_UUID"
        log "${BLUE}Sending data to TRMNL...${NC}"
        RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$WEBHOOK_URL" \
            -H "Content-Type: application/json" -d "$PAYLOAD")
        HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
        RESPONSE_BODY=$(echo "$RESPONSE" | sed '$d')
        if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "201" ]; then
            log "${GREEN}✓ Successfully sent to TRMNL${NC}"
        else
            log "${RED}✗ Failed to send to TRMNL (HTTP $HTTP_CODE)${NC}"
            log "${RED}Response: $RESPONSE_BODY${NC}"
        fi
    fi

    # Sleep until next scan
    NEXT_SCAN=$(date -d "+$INTERVAL minutes" "+%Y-%m-%d %H:%M:%S" 2>/dev/null || date -v+${INTERVAL}M "+%Y-%m-%d %H:%M:%S" 2>/dev/null || echo "in $INTERVAL minutes")
    log "${BLUE}Next scan at: $NEXT_SCAN${NC}"
    log "${BLUE}Sleeping for $INTERVAL minutes...${NC}"
    sleep "$SLEEP_SECONDS"
done
