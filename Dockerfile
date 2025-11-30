FROM alpine:latest

RUN apk add --no-cache bash curl jq nmap iproute2 iputils arp-scan

WORKDIR /app

COPY scan.sh /app/scan.sh
COPY device-db.json /app/device-db.json

RUN chmod +x /app/scan.sh

ENTRYPOINT ["/app/scan.sh"]
