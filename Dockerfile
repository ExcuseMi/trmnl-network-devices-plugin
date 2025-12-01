FROM python:3.13-alpine

# Install system dependencies
RUN apk add --no-cache \
    nmap \
    arp-scan \
    iproute2 \
    iputils \
    avahi-tools \
    bind-tools \
    curl

# Install Python dependencies
RUN pip install --no-cache-dir requests

WORKDIR /app

COPY scan.py /app/scan.py

RUN chmod +x /app/scan.py

ENTRYPOINT ["python3", "/app/scan.py"]