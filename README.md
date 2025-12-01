# Network Devices Plugin for TRMNL

Monitor all devices on your local network directly on your TRMNL display.

## Setup

### 1. Get Your Plugin UUID from TRMNL

1. Create a Private Plugin in TRMNL
2. Choose "Webhook" as data source
3. Copy your Plugin UUID from the webhook URL

### 2. Install on Your Raspberry Pi/Server

```bash
git clone https://github.com/ExcuseMi/trmnl-network-devices-plugin.git
cd trmnl-network-devices-plugin
cp .env.example .env
nano .env  # Add your PLUGIN_UUID
docker-compose up -d
```

That's it. The scanner will auto-detect your network and start sending data to TRMNL.

### Scanner Settings (.env file)

```bash
PLUGIN_UUID=your_plugin_uuid_here
INTERVAL=15        # Scan every 15 minutes
BYTE_LIMIT=2000    # 2000 for free, 5000 for TRMNL+
```

## Troubleshooting

**No devices showing?**
```bash
docker-compose logs -f network-scanner
```
                                
## Updating

```bash
cd trmnl-network-devices-plugin
git pull
docker-compose down
docker-compose build --no-cache
docker-compose up -d
```

## License

MIT

<!-- PLUGIN_STATS_START -->
## 🚀 TRMNL Plugin(s)

*Last updated: 2025-12-01 23:40:38 UTC*


## <img src="assets/plugin-images/189338_icon.png" alt="Network Devices icon" width="32"/> [Network Devices](https://usetrmnl.com/recipes/189338)

![Network Devices screenshot](assets/plugin-images/189338_screenshot.png)

### Description
Keep tabs on every device connected to your home or office network with automatic discovery, smart categorization, and real-time status tracking. Network Devices scans your local network, identifies devices by vendor and type, and displays them with intuitive icons on your TRMNL.<br /><br />Features:<br />• Automatic device detection via arp-scan and nmap<br />• Smart vendor identification from MAC addresses<br />• Offline tracking - see when devices disconnect<br />• Customizable names, icons, and device types<br />• Clean, modern interface with Material Symbols icons<br /><br />Requires a Docker container running on your network (5 min setup). Perfect for monitoring IoT devices, tracking network usage, or keeping an eye on who's connected.

### 📊 Statistics

| Metric | Value |
|--------|-------|
| Installs | 1 |
| Forks | 3 |

---

<!-- PLUGIN_STATS_END -->
