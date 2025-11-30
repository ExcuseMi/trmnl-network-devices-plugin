FROM alpine:latest

# Install nmap, curl, jq and other utilities
RUN apk add --no-cache nmap bash curl jq arp-scan

# Create a directory for scripts
WORKDIR /app

# Copy the scan script
COPY scan.sh /app/scan.sh
RUN chmod +x /app/scan.sh

# Run the scan script
ENTRYPOINT ["/app/scan.sh"]
