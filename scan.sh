#!/bin/bash

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log() { echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >&2; }

###############################################
# AUTO-DETECT LOCAL SUBNET (universal method)
###############################################
detect_subnet() {
    # Works even inside Docker
    local IFACE=$(ip route get 1.1.1.1 | awk '{print $5; exit}')
    local CIDR=$(ip -o -f inet addr show $IFACE | awk '{print $4}')

    log "${BLUE}Detected network: $CIDR${NC}"
    echo "$CIDR"
}

###############################################
# UNIVERSAL ARP SWEEP (probes even sleeping devices)
###############################################
arp_sweep() {
    local NETWORK=$1
    log "${BLUE}Performing ARP sweep...${NC}"

    # Expand network – nmap auto handles CIDR
    nmap -PR -sn "$NETWORK" -T5 --min-parallelism 100 --max-retries 1 2>/dev/null
}

###############################################
# PARSE ARP CACHE
###############################################
collect_arp_cache() {
    log "${BLUE}Reading ARP cache...${NC}"
    arp -an | awk '{
        if ($4 != "(incomplete)") {
            print "{\"ip\":\"" $2 "\",\"mac\":\"" $4 "\",\"method\":\"arp_cache\"}"
        }
    }' | sed 's/[()]//g'
}

###############################################
# PARSE DHCP LEASES (Linux universal fallback)
###############################################
collect_dhcp_leases() {
    local DHCP_DIRS=(
        "/var/lib/dhcp/"
        "/var/lib/dhclient/"
        "/var/lib/NetworkManager"
    )

    log "${BLUE}Checking local DHCP lease files...${NC}"

    for DIR in "${DHCP_DIRS[@]}"; do
        for FILE in "$DIR"/*; do
            if [[ -f "$FILE" ]]; then
                awk '
                    /lease/ { in_lea=1 }
                    /}/ { in_lea=0 }
                    in_lea {
                        if ($1=="hardware") mac=$3
                        if ($1=="fixed-address") ip=$2
                    }
                    /^}/ {
                        if (ip && mac) {
                            printf("{\"ip\":\"%s\",\"mac\":\"%s\",\"method\":\"dhcp_lease\"}\n", ip, mac)
                        }
                        ip=""
                        mac=""
                    }
                ' "$FILE"
            fi
        done
    done
}

###############################################
# NMAP RESULTS → JSON PARSING
###############################################
parse_nmap() {
    NMAP_OUTPUT="$1"

    echo "$NMAP_OUTPUT" | \
    awk '
        /Nmap scan report/ {
            ip=$NF; hostname=$(NF-1)
            if (hostname=="for") hostname=ip
        }
        /MAC Address/ {
            mac=$3
            vendor=$0
            sub(/.*\(|\).*/, "", vendor)
            printf("{\"ip\":\"%s\",\"hostname\":\"%s\",\"mac\":\"%s\",\"vendor\":\"%s\",\"method\":\"nmap\"}\n", ip, hostname, mac, vendor)
            ip=""; hostname=""; mac=""; vendor=""
        }
        END {
            if (ip) printf("{\"ip\":\"%s\",\"hostname\":\"%s\",\"mac\":\"\",\"vendor\":\"\",\"method\":\"nmap_no_mac\"}\n", ip, hostname)
        }
    '
}

###############################################
# MERGE + DEDUP DEVICES
###############################################
merge_all() {
    jq -s '
        flatten
        | group_by(.ip)
        | map(
            reduce .[] as $d (
                {};
                .ip = $d.ip // .ip //
                .hostname = $d.hostname // .hostname //
                .mac = $d.mac // .mac //
                .vendor = $d.vendor // .vendor //
                .method = (.method + "," + $d.method)
            )
        )
    '
}

###############################################
# MAIN EXECUTION
###############################################

echo -e "${GREEN}Starting UNIVERSAL network scanner...${NC}"

NETWORK=$(detect_subnet)
log "${YELLOW}Scanning network: $NETWORK${NC}"

# 1. nmap ARP scan
NMAP_RAW=$(arp_sweep "$NETWORK")
NMAP_JSON=$(parse_nmap "$NMAP_RAW")

# 2. ARP cache
ARP_JSON=$(collect_arp_cache)

# 3. DHCP leases
DHCP_JSON=$(collect_dhcp_leases)

# Combine all JSON lines
ALL_DEVICES=$(printf "%s\n%s\n%s\n" "$NMAP_JSON" "$ARP_JSON" "$DHCP_JSON")

# 4. MERGE + CLEAN JSON
FINAL=$(echo "$ALL_DEVICES" | merge_all)

# Output pretty list
echo -e "${BLUE}Devices detected:${NC}"
echo "$FINAL" | jq -r '.[] | "• \(.ip)  MAC:\(.mac)  Host:\(.hostname)  via \(.method)"'

# TRMNL integration (if PLUGIN_UUID set)
if [[ -n "$PLUGIN_UUID" ]]; then
    WEBHOOK="https://usetrmnl.com/api/custom_plugins/$PLUGIN_UUID"
    PAYLOAD=$(jq -n --argjson d "$FINAL" '{merge_variables:{devices_list:$d}}')

    curl -s -X POST "$WEBHOOK" \
        -H "Content-Type: application/json" \
        -d "$PAYLOAD" >/dev/null

    log "${GREEN}Sent updated device list to TRMNL${NC}"
fi
