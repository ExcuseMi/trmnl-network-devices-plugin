FROM alpine:latest

RUN apk add --no-cache nmap bash curl jq iproute2 iputils arp-scan

WORKDIR /app

COPY scan.sh /app/scan.sh
RUN chmod +x /app/scan.sh

ENTRYPOINT ["/app/scan.sh"]
