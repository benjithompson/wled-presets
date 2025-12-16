# WLED Presets Site

A simple single-page site for non-technical users to pick a WLED preset, plus an admin section to configure which WLED instances and presets are exposed.

## Why there is a tiny server
Browser-only HTML can’t reliably auto-discover devices on your LAN and usually can’t call the WLED HTTP API due to CORS restrictions. This project serves a single HTML page **and** provides a small local API that:
- discovers WLED devices on your subnet (default port 80)
- proxies/apply preset calls to WLED (based on https://kno.wled.ge/interfaces/http-api/)

## Run
1. Install deps:
   - `npm install`
2. Start:
   - `npm start`
3. Open:
   - http://localhost:8790

## Admin access
Set an admin token (recommended) and restart:
- `export ADMIN_TOKEN='your-long-random-string'`

Or change `adminToken` in `config.json`.

In the UI, open **Admin** and paste the token.

## Notes
- Discovery scans the server machine’s local IPv4 subnets and probes `http://<ip>/json/info`.
- Preset import reads `http://<device>/presets.json` and extracts preset IDs + names.

## Reliable discovery on a known subnet
If your WLED devices are on a known subnet (example: `192.168.20.0/24`), pin discovery to it:

- Option A (env var):
   - `export DISCOVERY_SUBNETS='192.168.20.0/24'`
   - `npm start`
- Option B (config file): set `discoverySubnets` in [config.json](config.json)

This avoids scanning the wrong interface/subnet on machines with multiple networks.

## Automatic discovery on startup (Docker/Unraid)
When running in Docker, especially with host network mode on Unraid, you can enable automatic discovery on container startup:

- `DISCOVERY_ON_STARTUP=1` - Enable automatic discovery when container starts (default: disabled)
- `DISCOVERY_AUTO_SAVE=1` - Automatically add newly discovered devices to configuration (default: disabled)
- `DISCOVERY_DEBUG=1` - Enable verbose discovery logging for troubleshooting (default: disabled)

**Example Docker run:**
```bash
docker run -d \
  --name wled-presets \
  --network host \
  -e DISCOVERY_ON_STARTUP=1 \
  -e DISCOVERY_AUTO_SAVE=1 \
  -e DISCOVERY_SUBNETS=192.168.1.0/24 \
  -e ADMIN_USERNAME=admin \
  -e ADMIN_PASSWORD=your-secure-password \
  -v /path/to/appdata:/app/data \
  benjitimate/wled-presets:latest
```

**Troubleshooting discovery issues:**
If discovery only finds some of your WLED devices:
1. Enable debug logging: `DISCOVERY_DEBUG=1`
2. Check the container logs to see which networks are being scanned
3. Verify all WLED devices are on the same subnet or specify multiple subnets via `DISCOVERY_SUBNETS`
4. Ensure WLED devices are powered on and accessible from the Docker host
5. Test manual discovery via the Admin interface after container starts
