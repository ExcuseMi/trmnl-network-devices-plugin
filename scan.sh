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
    hostname=$(getent hosts "$IP" 2>/dev/null | awk '{print $2}' | head -n1)

    # 3. Try host command (reverse DNS)
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
            hostname=$(timeout 1 avahi-resolve-address "$IP" 2>/dev/null | awk '{print $2}')
        fi
    fi

    # 6. Try NetBIOS name resolution (for Windows devices)
    if [ -z "$hostname" ] || [ "$hostname" = "$IP" ]; then
        if command -v nbtscan >/dev/null 2>&1; then
            hostname=$(timeout 2 nbtscan -q "$IP" 2>/dev/null | awk '{print $2}' | head -n1)
        fi
    fi

    # 7. Try nmblookup (alternative NetBIOS)
    if [ -z "$hostname" ] || [ "$hostname" = "$IP" ]; then
        if command -v nmblookup >/dev/null 2>&1; then
            hostname=$(timeout 2 nmblookup -A "$IP" 2>/dev/null | grep '<00>' | grep -v '<GROUP>' | awk '{print $1}' | head -n1)
        fi
    fi

    # 8. Extract from nmap's hostname detection if available
    # This is handled separately in the nmap section

    # Fallback to IP if nothing found
    [ -z "$hostname" ] && hostname="$IP"

    # Clean up hostname (remove trailing dots, spaces)
    hostname=$(echo "$hostname" | sed 's/\.$//' | xargs)

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

detect_device_type() {
    local hostname="$1"
    local vendor="$2"

    # Convert to lowercase for matching
    local h=$(echo "$hostname" | tr '[:upper:]' '[:lower:]')
    local v=$(echo "$vendor" | tr '[:upper:]' '[:lower:]')

    # Routers and Network Equipment
    if [[ "$v" =~ (tp-link|netgear|linksys|asus|ubiquiti|unifi|d-link|sagemcom) ]] || \
       [[ "$h" =~ (router|gateway|modem|access.*point) ]]; then
        echo "Router"
        return
    fi

    # Raspberry Pi
    if [[ "$v" =~ raspberry ]] || [[ "$h" =~ (raspberry|pi|pihole) ]]; then
        echo "Raspberry Pi"
        return
    fi

    # Printers
    if [[ "$v" =~ (brother|hp|epson|canon|lexmark) ]] || [[ "$h" =~ printer ]]; then
        echo "Printer"
        return
    fi

    # Smart Home Devices
    if [[ "$v" =~ (tuya|philips.*hue|wyze) ]] || [[ "$h" =~ (smart|hue|bulb|plug|switch) ]]; then
        echo "Smart Device"
        return
    fi

    # Speakers/Audio
    if [[ "$v" =~ (sonos|bose|slim.*devices) ]] || [[ "$h" =~ (speaker|sonos|squeezebox) ]]; then
        echo "Speaker"
        return
    fi

    # Apple Devices
    if [[ "$v" =~ apple ]] || [[ "$h" =~ (iphone|ipad|macbook|imac|airpod) ]]; then
        echo "Apple Device"
        return
    fi

    # Google Devices
    if [[ "$v" =~ google ]] || [[ "$h" =~ (chromecast|nest|google.*home) ]]; then
        echo "Google Device"
        return
    fi

    # Samsung
    if [[ "$v" =~ samsung ]] || [[ "$h" =~ (galaxy|samsung) ]]; then
        echo "Samsung Device"
        return
    fi

    # Computers/Laptops
    if [[ "$h" =~ (desktop|laptop|pc|macbook|imac|surface) ]]; then
        echo "Computer"
        return
    fi

    # Gaming
    if [[ "$v" =~ (sony|microsoft|nintendo|valve) ]] || \
       [[ "$h" =~ (playstation|xbox|ps4|ps5|switch|steamdeck|steam.*deck) ]]; then
        echo "Gaming Console"
        return
    fi

    # Phones/Tablets
    if [[ "$h" =~ (phone|mobile|tablet|ipad|galaxy.*tab) ]] || \
       [[ "$v" =~ (redmi.*pad|realtek.*wireless) ]]; then
        echo "Mobile Device"
        return
    fi

    # TV/Streaming
    if [[ "$v" =~ (roku|nvidia|lg|samsung.*tv|vizio) ]] || \
       [[ "$h" =~ (tv|roku|shield|appletv) ]]; then
        echo "TV/Streaming"
        return
    fi

    # Cameras
    if [[ "$h" =~ (camera|cam|doorbell) ]]; then
        echo "Camera"
        return
    fi

    # NAS/Storage
    if [[ "$h" =~ (nas|storage|synology|qnap) ]]; then
        echo "NAS"
        return
    fi

    # Default fallback
    echo "Network Device"
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
            device_type=$(detect_device_type "$hostname" "$vendor")

            jq --arg ip "$ip" \
               --arg hostname "$hostname" \
               --arg mac "$mac" \
               --arg vendor "$vendor" \
               --arg type "$device_type" \
               '. += [{"ip": $ip, "hostname": $hostname, "mac": $mac, "vendor": $vendor, "type": $type}]' \
               "$TEMP_FILE" > "$TEMP_FILE.tmp" && mv "$TEMP_FILE.tmp" "$TEMP_FILE"
        done <<< "$(echo "$ARP_OUTPUT" | awk '/([0-9]{1,3}\.){3}[0-9]{1,3}/ {print $1, $2, $3}')"
    else
        log "${YELLOW}arp-scan not found, skipping layer-2 scan${NC}"
    fi

    # ----------------------------
    # 2️⃣ Nmap fallback
    # ----------------------------
    # Use -sn for ping scan, -R for reverse DNS, --system-dns for better resolution
    NMAP_OUTPUT=$(nmap -sn -R --system-dns -T4 --max-retries 1 "$NETWORK" 2>/dev/null)

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
            DEVICE_TYPE=$(detect_device_type "$CURRENT_HOSTNAME" "$VENDOR")

            jq --arg ip "$CURRENT_IP" \
               --arg hostname "$CURRENT_HOSTNAME" \
               --arg mac "$MAC" \
               --arg vendor "$VENDOR" \
               --arg type "$DEVICE_TYPE" \
               '. += [{"ip": $ip, "hostname": $hostname, "mac": $mac, "vendor": $vendor, "type": $type}]' \
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
                    HOSTNAME=$(echo "$line" | sed -n 's/Nmap scan report for \(.*\)/\1/p' | sed 's/ (.*)$//')
                    if [ "$HOSTNAME" = "$IP" ] || [ -z "$HOSTNAME" ]; then
                        HOSTNAME=$(resolve_hostname "$IP")
                    fi
                    VENDOR=$(lookup_vendor "$LOCAL_MAC")
                    DEVICE_TYPE=$(detect_device_type "$HOSTNAME" "$VENDOR")

                    jq --arg ip "$IP" \
                       --arg hostname "$HOSTNAME" \
                       --arg mac "$LOCAL_MAC" \
                       --arg vendor "$VENDOR" \
                       --arg type "$DEVICE_TYPE" \
                       '. += [{"ip": $ip, "hostname": $hostname, "mac": $mac, "vendor": $vendor, "type": $type}]' \
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

    # ----------------------------
    # Add current scan devices
    # ----------------------------
    while IFS= read -r device; do
        IP=$(echo "$device" | jq -r '.ip')
        HOSTNAME=$(echo "$device" | jq -r '.hostname')
        MAC=$(echo "$device" | jq -r '.mac')
        VENDOR=$(echo "$device" | jq -r '.vendor')
        TYPE=$(echo "$device" | jq -r '.type // "Network Device"')

        IDENTIFIER="${MAC:-$IP}"

        [ "$HOSTNAME" = "$IP" ] && HOSTNAME=""

        DEVICE_STR="$IP|$HOSTNAME|$MAC|$VENDOR|$TYPE|$CURRENT_TIMESTAMP"
        DEVICES_ARRAY=$(echo "$DEVICES_ARRAY" | jq --arg d "$DEVICE_STR" '. += [$d]')

        CURRENT_MAP=$(echo "$CURRENT_MAP" | jq --arg id "$IDENTIFIER" \
            --arg ts "$CURRENT_TIMESTAMP" \
            --arg ip "$IP" --arg hostname "$HOSTNAME" \
            --arg mac "$MAC" --arg vendor "$VENDOR" --arg type "$TYPE" \
            '. + {($id): {last_seen: $ts, ip: $ip, hostname: $hostname, mac: $mac, vendor: $vendor, type: $type}}')
    done < <(echo "$DEVICES" | jq -c '.[]')

    # ----------------------------
    # Merge offline devices from previous state
    # ----------------------------
    if [ -f "$STATE_FILE" ]; then
        PREV=$(cat "$STATE_FILE")
        CUTOFF=$((CURRENT_TIMESTAMP - 86400)) # 24h retention

        for row in $(echo "$PREV" | jq -r 'to_entries | .[] | @base64'); do
            _jq() { echo "$row" | base64 --decode | jq -r "$1"; }

            ID=$(_jq '.key')
            TS=$(_jq '.value.last_seen')

            # Skip if device is in current scan
            IN_CURRENT=$(echo "$CURRENT_MAP" | jq --arg id "$ID" 'has($id)')
            if [ "$IN_CURRENT" = "true" ]; then
                continue
            fi

            # Only keep devices seen within retention window
            if [ "$TS" -le "$CUTOFF" ]; then
                continue
            fi

            P_IP=$(_jq '.value.ip')
            P_HN=$(_jq '.value.hostname')
            P_MAC=$(_jq '.value.mac')
            P_VEND=$(_jq '.value.vendor')
            P_TYPE=$(_jq '.value.type // "Network Device"')

            [ "$P_HN" = "$P_IP" ] && P_HN=""

            DEVICE_STR="$P_IP|$P_HN|$P_MAC|$P_VEND|$P_TYPE|$TS"
            DEVICES_ARRAY=$(echo "$DEVICES_ARRAY" | jq --arg d "$DEVICE_STR" '. += [$d]')

            CURRENT_MAP=$(echo "$CURRENT_MAP" | jq --arg id "$ID" \
                --arg ts "$TS" \
                --arg ip "$P_IP" --arg hostname "$P_HN" \
                --arg mac "$P_MAC" --arg vendor "$P_VEND" --arg type "$P_TYPE" \
                '. + {($id): {last_seen: $ts, ip: $ip, hostname: $hostname, mac: $mac, vendor: $vendor, type: $type}}')
        done
    fi

    # Save updated state
    echo "$CURRENT_MAP" > "$STATE_FILE"

    TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

    PAYLOAD=$(jq -n \
        --argjson devices "$DEVICES_ARRAY" \
        --arg timestamp "$TIMESTAMP" \
        '{ merge_variables: { devices_list: $devices, last_scan: $timestamp }}')

    PAYLOAD_SIZE=${#PAYLOAD}
    DEVICE_COUNT=$(echo "$DEVICES_ARRAY" | jq 'length')

    # ----------------------------
    # Truncate if over byte limit
    # ----------------------------
    if [ "$PAYLOAD_SIZE" -gt "$BYTE_LIMIT" ]; then
        log "${RED}WARNING: Payload ${PAYLOAD_SIZE} exceeds ${BYTE_LIMIT} bytes, truncating...${NC}"

        ONLINE_ARRAY='[]'
        OFFLINE_ARRAY='[]'

        for d in $(echo "$DEVICES_ARRAY" | jq -r '.[]'); do
            TS=$(echo "$d" | cut -d'|' -f6)
            if (( CURRENT_TIMESTAMP - TS < 600 )); then
                ONLINE_ARRAY=$(echo "$ONLINE_ARRAY" | jq --arg d "$d" '. += [$d]')
            else
                OFFLINE_ARRAY=$(echo "$OFFLINE_ARRAY" | jq --arg d "$d" '. += [$d]')
            fi
        done

        TRUNCATED_ARRAY='[]'

        # Add online first
        for d in $(echo "$ONLINE_ARRAY" | jq -r '.[]'); do
            TEST=$(echo "$TRUNCATED_ARRAY" | jq --arg d "$d" '. += [$d]')
            TEST_PAYLOAD=$(jq -n --argjson devices "$TEST" --arg timestamp "$TIMESTAMP" \
                '{ merge_variables: { devices_list: $devices, last_scan: $timestamp }}')
            (( ${#TEST_PAYLOAD} < BYTE_LIMIT-100 )) && TRUNCATED_ARRAY="$TEST" || break
        done

        # Add offline if space remains
        for d in $(echo "$OFFLINE_ARRAY" | jq -r '.[]'); do
            TEST=$(echo "$TRUNCATED_ARRAY" | jq --arg d "$d" '. += [$d]')
            TEST_PAYLOAD=$(jq -n --argjson devices "$TEST" --arg timestamp "$TIMESTAMP" \
                '{ merge_variables: { devices_list: $devices, last_scan: $timestamp }}')
            (( ${#TEST_PAYLOAD} < BYTE_LIMIT-100 )) && TRUNCATED_ARRAY="$TEST" || break
        done

        PAYLOAD=$(jq -n --argjson devices "$TRUNCATED_ARRAY" --arg timestamp "$TIMESTAMP" \
            '{ merge_variables: { devices_list: $devices, last_scan: $timestamp, truncated: true }}')

        PAYLOAD_SIZE=${#PAYLOAD}
        TRUNCATED_COUNT=$(echo "$TRUNCATED_ARRAY" | jq 'length')
        log "${YELLOW}Truncated payload size: ${PAYLOAD_SIZE} bytes (${TRUNCATED_COUNT} devices)${NC}"
    fi

    # ----------------------------
    # Send to TRMNL
    # ----------------------------
    WEBHOOK_URL="https://usetrmnl.com/api/custom_plugins/$PLUGIN_UUID"
    RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$WEBHOOK_URL" \
        -H "Content-Type: application/json" \
        -d "$PAYLOAD")

    HTTP_CODE=$(echo "$RESPONSE" | tail -n1)

    if [[ "$HTTP_CODE" =~ 20[01] ]]; then
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