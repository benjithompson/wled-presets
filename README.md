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
   - http://localhost:8787

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
