# WLED Presets Site

A simple web interface for selecting WLED presets, with an admin panel to manage devices and configure which presets are available.

## Features

- Public page for easy preset selection
- Auto-discovery of WLED devices on your network
- Device status polling with offline indicators
- Admin panel for configuration
- Multi-device preset groups

## Docker (Recommended)

```bash
docker run -d \
  --name wled-presets \
  --network host \
  -e ADMIN_USERNAME=admin \
  -e ADMIN_PASSWORD=your-secure-password \
  -e DISCOVERY_ON_STARTUP=1 \
  -e DISCOVERY_AUTO_SAVE=1 \
  -e DISCOVERY_SUBNETS=192.168.1.0/24 \
  -v /path/to/appdata:/app/data \
  ghcr.io/benjithompson/wled-presets:latest
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `ADMIN_USERNAME` | Admin login username | `admin` |
| `ADMIN_PASSWORD` | Admin login password | (required) |
| `PORT` | Web UI port | `8790` |
| `DISCOVERY_SUBNETS` | Subnet(s) to scan for WLED devices | Auto-detect |
| `DISCOVERY_ON_STARTUP` | Auto-discover devices on start | `0` |
| `DISCOVERY_AUTO_SAVE` | Auto-save discovered devices | `0` |
| `DISCOVERY_DEBUG` | Enable discovery debug logging | `0` |

### Docker Images

Available at `ghcr.io/benjithompson/wled-presets` (amd64/arm64)

Also on Docker Hub: `benjitimate/wled-presets`

## Local Development

```bash
npm install
npm start
```

Open http://localhost:8790
