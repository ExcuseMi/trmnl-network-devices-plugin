#!/bin/bash

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log() {
    echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >&2
}

#######################################
# Perform nmap scan and produce JSON
#######################################
perform_scan() {
    local NETWORK=$1
    log "${BLUE}Starting network scan on $NETWORK${NC}"

    SCAN_START=$(date +%s)
    SCAN_OUTPUT=$(nmap -sn -T5 --min-parallelism 100 --max-retries 1 "$NETWORK" 2>/dev/null)
    SCAN_END=$(date +%s)
    log "${YELLOW}Scan took $((SCAN_END - SCAN_START)) seconds${NC}"

    TEMP_FILE=$(mktemp)
    echo "[]" > "$TEMP_FILE"

    CURRENT_IP=""
    CURRENT_HOSTNAME=""
    CURRENT_MAC=""
    CURRENT_VENDOR=""

    while IFS= read -r line; do
        if [[ $line == *"Nmap scan report"* ]]; then
            # Store previous device if it had MAC or IP
            if [[ -n "$CURRENT_IP" ]]; then
                jq \
                    --arg ip "$CURRENT_IP" \
                    --arg hostname "$CURRENT_HOSTNAME" \
                    --arg mac "$CURRENT_MAC" \
                    --arg vendor "$CURRENT_VENDOR" \
                    '. += [{
                        ip: $ip,
                        hostname: $hostname,
                        mac: ($mac // ""),
                        vendor: ($vendor // "")
                    }]' "$TEMP_FILE" > "${TEMP_FILE}.new"

                mv "${TEMP_FILE}.new" "$TEMP_FILE"
            fi

            CURRENT_IP=$(echo "$line" | grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b')
            CURRENT_HOSTNAME=$(echo "$line" | sed -n 's/.*for \(.*\) (\(.*\))/\1/p')
            [[ -z "$CURRENT_HOSTNAME" ]] && \
                CURRENT_HOSTNAME=$(echo "$line" | sed -n 's/Nmap scan report for \(.*\)/\1/p')

            [[ -z "$CURRENT_HOSTNAME" ]] && CURRENT_HOSTNAME="$CURRENT_IP"
            CURRENT_MAC=""
            CURRENT_VENDOR=""

        elif [[ $line == *"MAC Address"* ]]; then
            CURRENT_MAC=$(echo "$line" | awk '{print $3}')
            CURRENT_VENDOR=$(echo "$line" | sed -E 's/.*\((.*)\).*/\1/')

            jq \
                --arg ip "$CURRENT_IP" \
                --arg hostname "$CURRENT_HOSTNAME" \
                --arg mac "$CURRENT_MAC" \
                --arg vendor "$CURRENT_VENDOR" \
                '. += [{
                    ip: $ip,
                    hostname: $hostname,
                    mac: $mac,
                    vendor: $vendor
                }]' "$TEMP_FILE" > "${TEMP_FILE}.new"

            mv "${TEMP_FILE}.new" "$TEMP_FILE"
            CURRENT_IP=""
            CURRENT_HOSTNAME=""
        fi
    done <<< "$SCAN_OUTPUT"

    # Final device (if no MAC line)
    if [[ -n "$CURRENT_IP" ]]; then
        jq \
            --arg ip "$CURRENT_IP" \
            --arg hostname "$CURRENT_HOSTNAME" \
            '. += [{
                ip: $ip,
                hostname: $hostname
            }]' "$TEMP_FILE" > "${TEMP_FILE}.new"

        mv "${TEMP_FILE}.new" "$TEMP_FILE"
    fi

    DEVICES=$(cat "$TEMP_FILE")
    rm "$TEMP_FILE"

    COUNT=$(echo "$DEVICES" | jq 'length')
    log "${GREEN}Found $COUNT devices${NC}"

    echo "$DEVICES"
}

#######################################
# Send payload to TRMNL
#######################################
send_to_trmnl() {
    local DEVICES="$1"
    local PLUGIN_UUID="$2"

    STATE_FILE="/tmp/network_scanner_state.json"
    CURRENT_TIMESTAMP=$(date +%s)

    [[ -f "$STATE_FILE" ]] && PREVIOUS=$(cat "$STATE_FILE") || PREVIOUS='{}'
    CURRENT='{}'
    ARRAY='[]'

    # Generate current device array
    while IFS= read -r row; do
        IP=$(echo "$row" | jq -r '.ip')
        HOST=$(echo "$row" | jq -r '.hostname // .ip')
        MAC=$(echo "$row" | jq -r '.mac // ""')
        VENDOR=$(echo "$row" | jq -r '.vendor // ""')

        IDENTIFIER="${MAC:-$IP}"

        ARRAY=$(echo "$ARRAY" | jq --arg d "$IP|$HOST|$MAC|$VENDOR|1" '. + [$d]')

        CURRENT=$(echo "$CURRENT" | jq \
            --arg id "$IDENTIFIER" \
            --arg ts "$CURRENT_TIMESTAMP" \
            --arg ip "$IP" \
            --arg host "$HOST" \
            --arg mac "$MAC" \
            --arg vendor "$VENDOR" \
            '
            . + {
                ($id): {
                    last_seen: ($ts | tonumber),
                    ip: $ip,
                    hostname: $host,
                    mac: $mac,
                    vendor: $vendor
                }
            }
            ')
    done < <(echo "$DEVICES" | jq -c '.[]')

    # Save state
    echo "$CURRENT" > "$STATE_FILE"

    TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

    PAYLOAD=$(jq -n \
        --argjson devices "$ARRAY" \
        --arg timestamp "$TIMESTAMP" \
        '
        {
            merge_variables: {
                devices_list: $devices,
                last_scan: $timestamp
            }
        }
        ')

    WEBHOOK="https://usetrmnl.com/api/custom_plugins/$PLUGIN_UUID"

    log "${BLUE}Sending to TRMNL...${NC}"
    log "${YELLOW}Payload bytes: ${#PAYLOAD}${NC}"

    curl -s -X POST "$WEBHOOK" \
        -H "Content-Type: application/json" \
        -d "$PAYLOAD" >/dev/null

    log "${GREEN}✓ Sent${NC}"
}

#######################################
# MAIN LOOP
#######################################

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}         Network Scanner v2             ${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

if [[ -n "$PLUGIN_UUID" ]]; then
    log "${GREEN}TRMNL mode enabled${NC}"
    INTERVAL=${INTERVAL:-5}
else
    log "${YELLOW}Single-scan mode${NC}"
fi

if [[ -z "$NETWORK" ]]; then
    GATEWAY=$(ip route | grep default | awk '{print $3}')
    NETWORK=$(echo "$GATEWAY" | awk -F'.' '{print $1"."$2"."$3".0/24"}')
fi

SCAN_COUNT=0

while true; do
    SCAN_COUNT=$((SCAN_COUNT + 1))
    log "${BLUE}--- Scan #$SCAN_COUNT ---${NC}"

    DEVICES=$(perform_scan "$NETWORK")

    echo "$DEVICES" | jq -r '.[] | "• \(.hostname) (\(.ip))" + (if .mac then " - \(.mac) [\(.vendor)]" else "" end)'
    echo ""

    if [[ -n "$PLUGIN_UUID" ]]; then
        send_to_trmnl "$DEVICES" "$PLUGIN_UUID"
        log "${BLUE}Sleeping ${INTERVAL}m...${NC}"
        sleep $((INTERVAL * 60))
    else
        log "${GREEN}Done.${NC}"
        exit 0
    fi
done
