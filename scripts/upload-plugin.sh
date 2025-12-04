#!/bin/bash

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if TRMNL_API_KEY is set
if [ -z "$TRMNL_API_KEY" ]; then
    echo -e "${RED}Error: TRMNL_API_KEY environment variable is not set${NC}"
    echo "Usage: export TRMNL_API_KEY='user_xxxxx'"
    exit 1
fi

# Check if zip file argument is provided
if [ -z "$1" ]; then
    echo -e "${RED}Error: No zip file provided${NC}"
    echo "Usage: $0 <plugin_archive.zip> [plugin_settings_id]"
    exit 1
fi

ZIP_FILE="$1"
PLUGIN_SETTINGS_ID="${2:-189338}"

# Check if zip file exists
if [ ! -f "$ZIP_FILE" ]; then
    echo -e "${RED}Error: File '$ZIP_FILE' not found${NC}"
    exit 1
fi

# Get file size
FILE_SIZE=$(stat -f%z "$ZIP_FILE" 2>/dev/null || stat -c%s "$ZIP_FILE" 2>/dev/null)

echo -e "${YELLOW}Uploading plugin archive...${NC}"
echo "  File: $ZIP_FILE ($FILE_SIZE bytes)"
echo "  Plugin Settings ID: $PLUGIN_SETTINGS_ID"
echo ""

# Upload the archive
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST \
    "https://usetrmnl.com/api/plugin_settings/${PLUGIN_SETTINGS_ID}/archive" \
    -H "Authorization: Bearer ${TRMNL_API_KEY}" \
    -H "User-Agent: trmnl-upload-script" \
    -F "file=@${ZIP_FILE}")

# Extract HTTP status code (last line) and body (everything else)
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)

# Check response
if [ "$HTTP_CODE" -eq 200 ]; then
    echo -e "${GREEN}✓ Upload successful!${NC}"
    echo ""
    echo "Response:"
    echo "$BODY" | python3 -m json.tool 2>/dev/null || echo "$BODY"
    echo ""
    echo -e "${GREEN}Dashboard: https://usetrmnl.com/plugin_settings/${PLUGIN_SETTINGS_ID}/edit${NC}"
else
    echo -e "${RED}✗ Upload failed with HTTP ${HTTP_CODE}${NC}"
    echo ""
    echo "Response:"
    echo "$BODY"
    exit 1
fi