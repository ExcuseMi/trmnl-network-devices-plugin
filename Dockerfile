FROM alpine:latest

# Install dependencies
RUN apk add --no-cache bash curl jq nmap iproute2 iputils arp-scan ca-certificates

WORKDIR /app

# Copy scan script
COPY scan.sh /app/scan.sh
RUN chmod +x /app/scan.sh

# Download IEEE OUI database
RUN curl -sSL https://standards-oui.ieee.org/oui/oui.txt -o /app/oui-raw.txt \
    && grep "(hex)" /app/oui-raw.txt | awk '{print $1 "\t" substr($0, index($0,$3))}' > /app/oui-db.txt \
    && rm /app/oui-raw.txt

# Create a sample device DB (users can extend)
RUN echo '{}' > /app/device-db.json

ENTRYPOINT ["/app/scan.sh"]
