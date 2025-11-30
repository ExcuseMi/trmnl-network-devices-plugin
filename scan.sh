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
    local hostname=""

    # Try multiple methods to resolve hostname
    # 1. Check cache first
    if [ -f "$STATE_FILE" ]; then
        hostname=$(jq -r --arg ip "$IP" '.[] | select(.ip==$ip) | .hostname // ""' "$STATE_FILE" 2>/dev/null)
        if [ ! -z "$hostname" ] && [ "$hostname" != "$IP" ]; then
            echo "$hostname"
            return
        fi
    fi

    # 2. Try getent (DNS/hosts file)
    hostname=$(getent hosts "$IP" | awk '{print $2}' | head -n1)

    # 3. Try host command
    if [ -z "$hostname" ] || [ "$hostname" = "$IP" ]; then
        hostname=$(host "$IP" 2>/dev/null | awk '/domain name pointer/ {print $5}' | sed 's/\.$//')
    fi

    # 4. Try nslookup
    if [ -z "$hostname" ] || [ "$hostname" = "$IP" ]; then
        hostname=$(nslookup "$IP" 2>/dev/null | awk '/name =/ {print $4}' | sed 's/\.$//' | head -n1)
    fi

    # 5. Try avahi/mdns for .local hostnames
    if [ -z "$hostname" ] || [ "$hostname" = "$IP" ]; then
        if command -v avahi-resolve-address >/dev/null 2>&1; then
            hostname=$(avahi-resolve-address "$IP" 2>/dev/null | awk '{print $2}')
        fi
    fi

    # Fallback to IP if nothing found
    [ -z "$hostname" ] && hostname="$IP"

    echo "$hostname"
}

get_local_mac() {
    local IP="$1"
    # Get MAC address for local IP from network interfaces
    ip addr show | awk -v ip="$IP" '
        /inet / {
            split($2, a, "/")
            current_ip = a[1]
        }
        /link\/ether/ && current_ip == ip {
            print toupper($2)
            exit
        }
    '
}

# State file for caching hostnames and tracking devices
STATE_FILE="/tmp/network_scanner_state.json"

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
            # Extract hostname and remove IP in parentheses if present
            CURRENT_HOSTNAME=$(echo "$line" | sed -n 's/Nmap scan report for \(.*\)/\1/p' | sed 's/ (.*)$//')
            # If hostname is just the IP, resolve it
            if [ "$CURRENT_HOSTNAME" = "$IP" ] || [ -z "$CURRENT_HOSTNAME" ]; then
                CURRENT_HOSTNAME=$(resolve_hostname "$IP")
            fi

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

    # ----------------------------
    # 3️⃣ Add devices without MAC (local device)
    # ----------------------------
    # Process nmap output again for devices without MAC addresses
    while IFS= read -r line; do
        if [[ $line == *"Nmap scan report"* ]]; then
            IP=$(echo "$line" | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b")

            # Check if device already has a MAC
            HAS_MAC=$(jq --arg ip "$IP" '[.[] | select(.ip==$ip)] | .[0].mac // ""' "$TEMP_FILE")

            if [ "$HAS_MAC" = '""' ]; then
                # This is likely the local device - try to get its MAC
                LOCAL_MAC=$(get_local_mac "$IP")

                if [ -n "$LOCAL_MAC" ]; then
                    HOSTNAME=$(echo "$line" | sed -n 's/Nmap scan report for \(.*\)/\1/p')
                    [ -z "$HOSTNAME" ] && HOSTNAME="$IP"
                    VENDOR=$(lookup_vendor "$LOCAL_MAC")

                    jq --arg ip "$IP" \
                       --arg hostname "$HOSTNAME" \
                       --arg mac "$LOCAL_MAC" \
                       --arg vendor "$VENDOR" \
                       '. += [{"ip": $ip, "hostname": $hostname, "mac": $mac, "vendor": $vendor}]' \
                       "$TEMP_FILE" > "$TEMP_FILE.tmp" && mv "$TEMP_FILE.tmp" "$TEMP_FILE"
                fi
            fi
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
    CURRENT_TIMESTAMP=$(date +%s)

    CURRENT_MAP='{}'
    DEVICES_ARRAY='[]'

    # Build current list with current timestamp
    while IFS= read -r device; do
        IP=$(echo "$device" | jq -r '.ip')
        HOSTNAME=$(echo "$device" | jq -r '.hostname')
        MAC=$(echo "$device" | jq -r '.mac')
        VENDOR=$(echo "$device" | jq -r '.vendor')

        IDENTIFIER="${MAC:-$IP}"

        # Don't send hostname if it's same as IP (save bytes)
        if [ "$HOSTNAME" = "$IP" ]; then
            HOSTNAME=""
        fi

        # Send actual timestamp instead of 1
        DEVICE_STR="$IP|$HOSTNAME|$MAC|$VENDOR|$CURRENT_TIMESTAMP"
        DEVICES_ARRAY=$(echo "$DEVICES_ARRAY" | jq --arg d "$DEVICE_STR" '. += [$d]')

        CURRENT_MAP=$(echo "$CURRENT_MAP" | jq --arg id "$IDENTIFIER" \
            --arg ts "$CURRENT_TIMESTAMP" \
            --arg ip "$IP" --arg hostname "$HOSTNAME" \
            --arg mac "$MAC" --arg vendor "$VENDOR" \
            '. + {($id): {last_seen: $ts, ip: $ip, hostname: $hostname, mac: $mac, vendor: $vendor}}')

    done < <(echo "$DEVICES" | jq -c '.[]')

    # Merge offline devices with their last seen timestamp
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

                # Don't send hostname if it's same as IP (save bytes)
                if [ "$P_HN" = "$P_IP" ]; then
                    P_HN=""
                fi

                # Send the old timestamp (when it was last seen)
                DEVICE_STR="$P_IP|$P_HN|$P_MAC|$P_VEND|$TS"
                DEVICES_ARRAY=$(echo "$DEVICES_ARRAY" | jq --arg d "$DEVICE_STR" '. += [$d]')
            fi
        done
    fi

    echo "$CURRENT_MAP" > "$STATE_FILE"

    TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

    # Build initial payload to check size
    PAYLOAD=$(jq -n \
        --argjson devices "$DEVICES_ARRAY" \
        --arg timestamp "$TIMESTAMP" \
        '{ merge_variables: { devices_list: $devices, last_scan: $timestamp }}')

    PAYLOAD_SIZE=${#PAYLOAD}
    DEVICE_COUNT=$(echo "$DEVICES_ARRAY" | jq 'length')

    WEBHOOK_URL="https://usetrmnl.com/api/custom_plugins/$PLUGIN_UUID"

    log "${BLUE}Sending to TRMNL...${NC}"
    log "${YELLOW}Payload size: ${PAYLOAD_SIZE} bytes (limit: ${BYTE_LIMIT}, devices: ${DEVICE_COUNT})${NC}"

    # If payload exceeds limit, truncate devices (prioritize online devices)
    if [ "$PAYLOAD_SIZE" -gt "$BYTE_LIMIT" ]; then
        log "${RED}WARNING: Payload is ${PAYLOAD_SIZE} bytes (limit: ${BYTE_LIMIT})${NC}"
        log "${YELLOW}Truncating device list (keeping online devices first)...${NC}"

        # Separate online and offline devices
        ONLINE_ARRAY='[]'
        OFFLINE_ARRAY='[]'

        DEVICE_STRINGS=$(echo "$DEVICES_ARRAY" | jq -r '.[]')
        while IFS= read -r device_str; do
            TS=$(echo "$device_str" | cut -d'|' -f5)
            TIME_DIFF=$((CURRENT_TIMESTAMP - TS))

            # If seen within last 10 minutes, it's online
            if [ "$TIME_DIFF" -lt 600 ]; then
                ONLINE_ARRAY=$(echo "$ONLINE_ARRAY" | jq --arg d "$device_str" '. += [$d]')
            else
                OFFLINE_ARRAY=$(echo "$OFFLINE_ARRAY" | jq --arg d "$device_str" '. += [$d]')
            fi
        done <<< "$DEVICE_STRINGS"

        # Add online devices first, then offline until we hit limit
        TRUNCATED_ARRAY='[]'

        # Add all online devices first
        echo "$ONLINE_ARRAY" | jq -r '.[]' | while read -r device_str; do
            TEST_ARRAY=$(echo "$TRUNCATED_ARRAY" | jq --arg d "$device_str" '. += [$d]')
            TEST_PAYLOAD=$(jq -n \
                --argjson devices "$TEST_ARRAY" \
                --arg timestamp "$TIMESTAMP" \
                '{ merge_variables: { devices_list: $devices, last_scan: $timestamp }}')

            if [ ${#TEST_PAYLOAD} -lt $((BYTE_LIMIT - 100)) ]; then
                TRUNCATED_ARRAY="$TEST_ARRAY"
            else
                break
            fi
        done

        # Add offline devices if space remains
        echo "$OFFLINE_ARRAY" | jq -r '.[]' | while read -r device_str; do
            TEST_ARRAY=$(echo "$TRUNCATED_ARRAY" | jq --arg d "$device_str" '. += [$d]')
            TEST_PAYLOAD=$(jq -n \
                --argjson devices "$TEST_ARRAY" \
                --arg timestamp "$TIMESTAMP" \
                '{ merge_variables: { devices_list: $devices, last_scan: $timestamp }}')

            if [ ${#TEST_PAYLOAD} -lt $((BYTE_LIMIT - 100)) ]; then
                TRUNCATED_ARRAY="$TEST_ARRAY"
            else
                break
            fi
        done

        TRUNCATED_COUNT=$(echo "$TRUNCATED_ARRAY" | jq 'length')

        PAYLOAD=$(jq -n \
            --argjson devices "$TRUNCATED_ARRAY" \
            --arg timestamp "$TIMESTAMP" \
            '{ merge_variables: { devices_list: $devices, last_scan: $timestamp, truncated: true }}')

        PAYLOAD_SIZE=${#PAYLOAD}
        log "${YELLOW}Truncated payload size: ${PAYLOAD_SIZE} bytes (showing ${TRUNCATED_COUNT} of ${DEVICE_COUNT} devices)${NC}"
    fi

    # Final safety check
    if [ "$PAYLOAD_SIZE" -gt "$BYTE_LIMIT" ]; then
        log "${RED}ERROR: Payload still exceeds limit after truncation (${PAYLOAD_SIZE} bytes)${NC}"
        return 1
    fi

    RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$WEBHOOK_URL" \
        -H "Content-Type: application/json" \
        -d "$PAYLOAD")

    HTTP_CODE=$(echo "$RESPONSE" | tail -n1)

    if [[ "$HTTP_CODE" == 200 || "$HTTP_CODE" == 201 ]]; then
        log "${GREEN}✓ Sent successfully (${PAYLOAD_SIZE} bytes, ${DEVICE_COUNT} devices)${NC}"
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
done