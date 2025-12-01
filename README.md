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

*Last updated: 2025-12-01 15:43:53 UTC*


## 🔒 Plugin ID: 189338

**Status**: ⏳ Not yet published on TRMNL or API unavailable

This plugin is configured but either hasn't been published to the TRMNL marketplace yet or the API is temporarily unavailable.

**Plugin URL**: https://usetrmnl.com/recipes/189338

---

<!-- PLUGIN_STATS_END -->
