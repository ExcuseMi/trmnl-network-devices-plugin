FROM alpine:latest

RUN apk add --no-cache bash curl jq nmap iproute2 iputils arp-scan avahi-tools bind-tools

WORKDIR /app

COPY scan.sh /app/scan.sh

RUN chmod +x /app/scan.sh

ENTRYPOINT ["/app/scan.sh"]