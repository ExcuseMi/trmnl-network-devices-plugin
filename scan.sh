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

# Function to perform network scan
perform_scan() {
    local NETWORK=$1

    log "${BLUE}Starting network scan on $NETWORK${NC}"

    # Start timer
    SCAN_START=$(date +%s)

    # Perform the scan and capture output
    # -sn: Ping scan (no port scan)
    # -T5: Insane timing (fastest)
    # --min-parallelism 100: Scan many hosts in parallel
    # --max-retries 1: Don't retry if host doesn't respond
    SCAN_OUTPUT=$(nmap -sn -T5 --min-parallelism 100 --max-retries 1 $NETWORK 2>/dev/null)

    # End timer
    SCAN_END=$(date +%s)
    SCAN_DURATION=$((SCAN_END - SCAN_START))
    log "${YELLOW}Scan took ${SCAN_DURATION} seconds${NC}"

    # Parse nmap output into JSON using a temporary file for safety
    TEMP_FILE=$(mktemp)
    echo "[]" > "$TEMP_FILE"

    CURRENT_IP=""
    CURRENT_HOSTNAME=""

    while IFS= read -r line; do
        if [[ $line == *"Nmap scan report"* ]]; then
            # Save previous device if exists
            if [ ! -z "$CURRENT_IP" ]; then
                # Use jq to properly escape all values and add device
                TEMP_CONTENT=$(cat "$TEMP_FILE")
                echo "$TEMP_CONTENT" | jq --arg ip "$CURRENT_IP" \
                    --arg hostname "$CURRENT_HOSTNAME" \
                    '. += [{"ip": $ip, "hostname": $hostname}]' > "$TEMP_FILE"
            fi

            # Extract new IP
            CURRENT_IP=$(echo "$line" | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b")

            # Extract hostname
            CURRENT_HOSTNAME=$(echo "$line" | sed -n 's/.*for \(.*\) (\(.*\))/\1/p')
            if [ -z "$CURRENT_HOSTNAME" ]; then
                CURRENT_HOSTNAME=$(echo "$line" | sed -n 's/Nmap scan report for \(.*\)/\1/p')
            fi
            # Default to IP if hostname is empty
            if [ -z "$CURRENT_HOSTNAME" ]; then
                CURRENT_HOSTNAME="$CURRENT_IP"
            fi

        elif [[ $line == *"MAC Address"* ]] && [ ! -z "$CURRENT_IP" ]; then
            MAC=$(echo "$line" | awk '{print $3}')
            VENDOR=$(echo "$line" | cut -d'(' -f2 | cut -d')' -f1)

            # Add device with MAC info using jq
            TEMP_CONTENT=$(cat "$TEMP_FILE")
            echo "$TEMP_CONTENT" | jq --arg ip "$CURRENT_IP" \
                --arg hostname "$CURRENT_HOSTNAME" \
                --arg mac "$MAC" \
                --arg vendor "$VENDOR" \
                '. += [{"ip": $ip, "hostname": $hostname, "mac": $mac, "vendor": $vendor}]' > "$TEMP_FILE"

            # Reset
            CURRENT_IP=""
            CURRENT_HOSTNAME=""
        fi
    done <<< "$SCAN_OUTPUT"

    # Add last device if it exists (device without MAC)
    if [ ! -z "$CURRENT_IP" ]; then
        TEMP_CONTENT=$(cat "$TEMP_FILE")
        echo "$TEMP_CONTENT" | jq --arg ip "$CURRENT_IP" \
            --arg hostname "$CURRENT_HOSTNAME" \
            '. += [{"ip": $ip, "hostname": $hostname}]' > "$TEMP_FILE"
    fi

    # Read the final JSON
    DEVICES=$(cat "$TEMP_FILE")
    rm "$TEMP_FILE"

    # Get device count
    DEVICE_COUNT=$(echo "$DEVICES" | jq 'length')

    log "${GREEN}Found $DEVICE_COUNT devices${NC}"

    # Debug: Show the devices JSON
    log "${YELLOW}DEBUG - Devices JSON:${NC}"
    echo "$DEVICES" | jq '.' >&2

    echo "$DEVICES"
}

# Function to send data to TRMNL webhook
send_to_trmnl() {
    local DEVICES=$1
    local PLUGIN_UUID=$2

    # Get byte limit from environment variable (default: 2000)
    BYTE_LIMIT=${BYTE_LIMIT:-2000}

    # State file to track last seen devices
    STATE_FILE="/tmp/network_scanner_state.json"

    # Load previous state if exists
    if [ -f "$STATE_FILE" ]; then
        PREVIOUS_DEVICES=$(cat "$STATE_FILE")
    else
        PREVIOUS_DEVICES='{}'
    fi

    # Create current device map with timestamp
    CURRENT_TIMESTAMP=$(date +%s)
    CURRENT_MAP='{}'

    # Build current device map
    echo "$DEVICES" | jq -r '.[] | "\(.mac // .ip)"' | while read -r identifier; do
        if [ ! -z "$identifier" ]; then
            CURRENT_MAP=$(echo "$CURRENT_MAP" | jq --arg id "$identifier" --arg ts "$CURRENT_TIMESTAMP" \
                '. + {($id): {last_seen: $ts}}')
        fi
    done

    # Create compact array with offline status
    # Format: ["IP|Hostname|MAC|Vendor|offline", ...]
    DEVICES_ARRAY='[]'

    while IFS= read -r device; do
        IP=$(echo "$device" | jq -r '.ip')
        HOSTNAME=$(echo "$device" | jq -r '.hostname // .ip')
        MAC=$(echo "$device" | jq -r '.mac // ""')
        VENDOR=$(echo "$device" | jq -r '.vendor // ""')

        # Device is online (in current scan)
        IDENTIFIER="${MAC:-$IP}"
        DEVICE_STR="$IP|$HOSTNAME|$MAC|$VENDOR|1"

        DEVICES_ARRAY=$(echo "$DEVICES_ARRAY" | jq --arg d "$DEVICE_STR" '. += [$d]')

        # Update state with current timestamp
        CURRENT_MAP=$(echo "$CURRENT_MAP" | jq --arg id "$IDENTIFIER" --arg ts "$CURRENT_TIMESTAMP" \
            '. + {($id): {last_seen: $ts, hostname: "'$HOSTNAME'", ip: "'$IP'", mac: "'$MAC'", vendor: "'$VENDOR'"}}')
    done < <(echo "$DEVICES" | jq -c '.[]')

    # Add previously seen devices that are now offline (not in current scan)
    # Only include devices seen in the last 24 hours
    CUTOFF_TIME=$((CURRENT_TIMESTAMP - 86400))

    if [ "$PREVIOUS_DEVICES" != '{}' ]; then
        echo "$PREVIOUS_DEVICES" | jq -r 'to_entries | .[] | @json' | while IFS= read -r entry; do
            PREV_ID=$(echo "$entry" | jq -r '.key')
            PREV_DATA=$(echo "$entry" | jq -r '.value')
            PREV_TIMESTAMP=$(echo "$PREV_DATA" | jq -r '.last_seen')

            # Check if device is in current scan
            IS_CURRENT=$(echo "$CURRENT_MAP" | jq --arg id "$PREV_ID" 'has($id)')

            # If device was seen recently but not in current scan, mark as offline
            if [ "$IS_CURRENT" = "false" ] && [ "$PREV_TIMESTAMP" -gt "$CUTOFF_TIME" ]; then
                PREV_IP=$(echo "$PREV_DATA" | jq -r '.ip // ""')
                PREV_HOSTNAME=$(echo "$PREV_DATA" | jq -r '.hostname // ""')
                PREV_MAC=$(echo "$PREV_DATA" | jq -r '.mac // ""')
                PREV_VENDOR=$(echo "$PREV_DATA" | jq -r '.vendor // ""')

                if [ ! -z "$PREV_IP" ]; then
                    DEVICE_STR="$PREV_IP|$PREV_HOSTNAME|$PREV_MAC|$PREV_VENDOR|0"
                    DEVICES_ARRAY=$(echo "$DEVICES_ARRAY" | jq --arg d "$DEVICE_STR" '. += [$d]')
                fi
            fi
        done
    fi

    # Save current state for next scan
    echo "$CURRENT_MAP" > "$STATE_FILE"

    TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

    # Build initial payload to check size
    PAYLOAD=$(jq -n \
        --argjson devices "$DEVICES_ARRAY" \
        --arg timestamp "$TIMESTAMP" \
        '{
            merge_variables: {
                devices_list: $devices,
                last_scan: $timestamp
            }
        }')

    # Check payload size
    PAYLOAD_SIZE=${#PAYLOAD}

    # Send to TRMNL
    WEBHOOK_URL="https://usetrmnl.com/api/custom_plugins/$PLUGIN_UUID"

    log "${BLUE}Sending data to TRMNL...${NC}"
    log "${YELLOW}Payload size: ${PAYLOAD_SIZE} bytes (limit: ${BYTE_LIMIT})${NC}"

    # If payload exceeds limit, truncate devices
    if [ "$PAYLOAD_SIZE" -gt "$BYTE_LIMIT" ]; then
        log "${RED}WARNING: Payload is ${PAYLOAD_SIZE} bytes (limit: ${BYTE_LIMIT})${NC}"
        log "${YELLOW}Truncating device list...${NC}"

        TRUNCATED_ARRAY="[]"
        DEVICE_STRINGS=$(echo "$DEVICES_ARRAY" | jq -r '.[]')

        # Add devices one by one until we approach the limit
        while IFS= read -r device_str; do
            # Test adding this device
            TEST_ARRAY=$(echo "$TRUNCATED_ARRAY" | jq --arg device "$device_str" '. += [$device]')

            TEST_PAYLOAD=$(jq -n \
                --argjson devices "$TEST_ARRAY" \
                --arg timestamp "$TIMESTAMP" \
                '{
                    merge_variables: {
                        devices_list: $devices,
                        last_scan: $timestamp,
                        truncated: true
                    }
                }')

            # Leave safety margin of 100 bytes
            if [ ${#TEST_PAYLOAD} -lt $((BYTE_LIMIT - 100)) ]; then
                TRUNCATED_ARRAY="$TEST_ARRAY"
            else
                break
            fi
        done <<< "$DEVICE_STRINGS"

        TRUNCATED_COUNT=$(echo "$TRUNCATED_ARRAY" | jq 'length')
        TOTAL_COUNT=$(echo "$DEVICES_ARRAY" | jq 'length')

        PAYLOAD=$(jq -n \
            --argjson devices "$TRUNCATED_ARRAY" \
            --arg timestamp "$TIMESTAMP" \
            '{
                merge_variables: {
                    devices_list: $devices,
                    last_scan: $timestamp,
                    truncated: true
                }
            }')

        PAYLOAD_SIZE=${#PAYLOAD}
        log "${YELLOW}Truncated payload size: ${PAYLOAD_SIZE} bytes (showing $TRUNCATED_COUNT of $TOTAL_COUNT devices)${NC}"
    fi

    # Final safety check - should never trigger but just in case
    if [ "$PAYLOAD_SIZE" -gt "$BYTE_LIMIT" ]; then
        log "${RED}ERROR: Payload still exceeds limit after truncation (${PAYLOAD_SIZE} bytes)${NC}"
        log "${RED}This should not happen - please report this issue${NC}"
        return 1
    fi

    # Debug: Show what we're sending
    log "${YELLOW}DEBUG - Payload being sent:${NC}"
    echo "$PAYLOAD" | jq '.' >&2

    RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$WEBHOOK_URL" \
        -H "Content-Type: application/json" \
        -d "$PAYLOAD")

    HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
    RESPONSE_BODY=$(echo "$RESPONSE" | sed '$d')

    if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "201" ]; then
        log "${GREEN}✓ Successfully sent to TRMNL${NC}"
        return 0
    elif [ "$HTTP_CODE" = "429" ]; then
        log "${YELLOW}⚠ Rate limited by TRMNL (429) - will retry later${NC}"
        return 1
    else
        log "${RED}✗ Failed to send to TRMNL (HTTP $HTTP_CODE)${NC}"
        log "${RED}Response: $RESPONSE_BODY${NC}"
        return 1
    fi
}

# Main script
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  Network Scanner with TRMNL${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Check for required environment variables if TRMNL mode is enabled
if [ ! -z "$PLUGIN_UUID" ]; then
    log "${GREEN}TRMNL mode enabled${NC}"
    log "${BLUE}Plugin UUID: $PLUGIN_UUID${NC}"

    # Set default interval if not specified
    INTERVAL=${INTERVAL:-15}
    log "${BLUE}Scan interval: $INTERVAL minutes${NC}"

    # Validate interval is not too frequent (max 12 per hour = 5 minutes minimum)
    if [ "$INTERVAL" -lt 5 ]; then
        log "${YELLOW}Warning: Interval less than 5 minutes may exceed TRMNL rate limits${NC}"
        log "${YELLOW}Consider upgrading to TRMNL+ for higher limits${NC}"
    fi
else
    log "${YELLOW}TRMNL mode disabled (no PLUGIN_UUID provided)${NC}"
    log "${YELLOW}Running in single-scan mode${NC}"
fi

# Auto-detect or use provided network
if [ -z "$NETWORK" ]; then
    log "${YELLOW}No NETWORK specified, attempting auto-detection...${NC}"

    GATEWAY=$(ip route | grep default | awk '{print $3}')

    if [ -z "$GATEWAY" ]; then
        log "${RED}Could not detect network automatically.${NC}"
        log "${YELLOW}Please run with: docker run --network host -e NETWORK=192.168.1.0/24 network-scanner${NC}"
        exit 1
    fi

    NETWORK=$(echo $GATEWAY | cut -d'.' -f1-3).0/24
    log "${GREEN}Auto-detected network: $NETWORK${NC}"
else
    log "${GREEN}Using network: $NETWORK${NC}"
fi

echo ""

# Run scan loop
SCAN_COUNT=0
while true; do
    SCAN_COUNT=$((SCAN_COUNT + 1))

    log "${BLUE}--- Scan #$SCAN_COUNT ---${NC}"

    # Perform the scan
    DEVICES=$(perform_scan "$NETWORK")

    # Display devices in console
    echo "$DEVICES" | jq -r '.[] | "  • \(.hostname) (\(.ip))" + (if .mac then " - \(.mac) [\(.vendor)]" else "" end)'

    echo ""

    # Send to TRMNL if configured
    if [ ! -z "$PLUGIN_UUID" ]; then
        # Debug: Check if DEVICES is valid JSON
        if ! echo "$DEVICES" | jq empty 2>/dev/null; then
            log "${RED}ERROR - DEVICES is not valid JSON!${NC}"
            log "${RED}DEVICES content: $DEVICES${NC}"
        else
            send_to_trmnl "$DEVICES" "$PLUGIN_UUID"
        fi
        echo ""

        # Calculate seconds until next scan
        SLEEP_SECONDS=$((INTERVAL * 60))
        NEXT_SCAN=$(date -d "+${INTERVAL} minutes" "+%Y-%m-%d %H:%M:%S" 2>/dev/null || date -v+${INTERVAL}M "+%Y-%m-%d %H:%M:%S" 2>/dev/null || echo "in ${INTERVAL} minutes")

        log "${BLUE}Next scan at: $NEXT_SCAN${NC}"
        log "${BLUE}Sleeping for $INTERVAL minutes...${NC}"

        sleep $SLEEP_SECONDS
    else
        # Single scan mode - exit after first scan
        log "${GREEN}Scan complete!${NC}"
        break
    fi
done