# WLED Presets

A web page where anyone on your network can control all your WLED lights at once, and an admin console to set it up.

- **Public page** — tap a **scene** to play a preset on every device, or pick a solid color. Live status shows which lights are online. Light and dark themes. Works well on phones and can be added to the home screen.
- **Admin console** (`/admin`)
  - **Scenes** — create, edit, reorder, test, export and import. Each scene maps one WLED preset to each device. "Quick fill" maps every device that has a preset with the same name.
  - **Devices** — add by address or scan the network. The presets stored on a device are imported when you add it, and again when its address changes; **Import** reads them again at any time. Play a preset to test it, and enable or disable a device.
  - **Layout** — place every light object where it really is, in 3D: rooflines, other lines of lights (windows, doors, a fence, a path), bushes and trees (a spiral, or strands that zigzag). The front view (over a picture of the house) moves objects across and up, the top view across and toward the street, and the 3D view (three.js, loaded only when opened) shows the whole yard with glowing LEDs; click an LED there to select its object. A measure tool sets the real scale (feet or meters), a ground line sets height 0, and the side panel takes exact positions. LEDs spread along the real 3D length of a line, so a roofline that runs back along the side of the house gets its share. Each object has the number of LEDs in it. Games and the simulator use this map. Each object has a WLED device and the LED numbers at its first and last point; LEDs between objects (gaps, a hidden side of the house) stay off. A roof line can be split at a corner, and a corner can be pinned to its real LED number. Click one straight segment of a roof line to light up only that segment, set its start and end LED (segments never share an LED: when one segment ends at LED 49, the next starts at 50), or turn it off (skipped: for a stretch that only links two lit segments; its LEDs stay dark and games skip it). While you edit, the selected object glows blue on the simulator and the real lights (first LED green, last LED red, corners amber), and each change to its LED numbers shows at once through DDP over UDP (port 4048). The lights go back to normal about 2 seconds after you leave the editor.
  - **Real lights** — a running game also goes to each object's WLED device; when the game ends (or the last Play page closes), each device goes straight back to its color, scene or preset. On the Play page, a signed-in admin can open **Debug** to turn this off or limit the brightness. The game goes to each object's WLED device (up to 60 frames per second, DDP over UDP: long strips go in several packets and show as one frame), with a brightness limit. Objects with no device stay in the simulator. Nothing is sent while no game runs. If DDP does not reach a device (for example, a router between two networks drops it), the app falls back to the WLED JSON API over HTTP at about 12 frames per second, and says so in the debug panel and the Activity log.
  - **Activity** — live log of what was applied, by whom, and every admin change.
  - **Settings** — page title and subtitle, color picker on or off, default scene and auto-revert time, discovery subnets, admin password.

- **Play** (`/play`) — games that use the lights on the house, controlled from a phone with one big button. For now the games run in a simulator of the yard; sending them to the real lights comes next. First game: **Comet Catcher** — stop the comet inside the green gate on the roof; each catch lights a bush.

A *scene* is what v1 called a *public preset*. A *WLED preset* is a preset stored on one device.

## Run with Docker

```bash
docker run -d \
  --name wled-presets \
  --network host \
  -e ADMIN_USERNAME=admin \
  -e ADMIN_PASSWORD=change-me-to-something-long \
  -e DISCOVERY_ON_STARTUP=1 \
  -e DISCOVERY_AUTO_SAVE=1 \
  -v /path/to/appdata:/app/data \
  ghcr.io/benjithompson/wled-presets:latest
```

Or use [docker-compose.yml](docker-compose.yml). Then open `http://<host>:8790`.

Host networking lets discovery scan your LAN. Without it, add devices by IP address.

### Environment variables

| Variable | Default | Description |
|---|---|---|
| `ADMIN_USERNAME` / `ADMIN_PASSWORD` | — | Creates the first admin account when none exists. Ignored after that. |
| `PORT` | `8790` | Web port. |
| `DATABASE_PATH` | `/app/data/wled-presets.sqlite` | SQLite file. |
| `PUID` / `PGID` | `99` / `100` | Owner of the data folder. The server runs as this user. |
| `DISCOVERY_ON_STARTUP` | `0` | Scan for devices when the container starts. |
| `DISCOVERY_AUTO_SAVE` | `0` | Add devices found by the startup scan. |
| `DISCOVERY_SUBNETS` | auto | Comma-separated CIDR ranges to scan. Overrides the subnets in Settings. |
| `DISCOVERY_DEBUG` | `0` | Log discovery details. |
| `DISCOVERY_HOSTS` | — | Extra hosts to probe on every scan, comma-separated. |
| `DISCOVERY_PORTS` | `80` | Ports to probe on each address, for example `80,8080` or `9101-9104`. |
| `STATUS_INTERVAL_MS` | `10000` | How often device status is checked. |
| `SECURE_COOKIE` | `0` | Set to `1` when you reach the app only over HTTPS. |
| `TRUST_PROXY` | `0` | Set to `1` behind a reverse proxy, so logs show the real client IP. |

With no admin account and no environment variables, open `/admin` from the server itself to create one.

## Upgrade from v1

Point v2 at the same data folder. It reads the v1 database as it is: devices, public presets (now scenes), imported presets, the default preset and the auto-revert time all carry over. The public page keeps its "Christmas Lights" title; change it in Settings.

What changes:

- Admins sign in once more, because sessions are now stored in the main database. `SESSION_SECRET` is no longer used.
- Cookies are no longer `Secure` by default. Set `SECURE_COOKIE=1` if you use HTTPS.
- v1 backup files still import. v2 backups also store device addresses, so a backup restores onto a new install.

## Development

Requires Node.js 24 or newer.

To start everything with one command:

```bash
./run.sh
```

The script installs dependencies and creates `.env` when they are missing. Then it starts four fake WLED devices, the API, and the web client. It also sets `DISCOVERY_HOSTS` and `DISCOVERY_PORTS`, so **Discover** finds the fake devices. Open http://localhost:5790. Press Ctrl+C to stop all three.

To run the parts one at a time:

| Command | What it does |
|---|---|
| `npm run dev:all` | Same as `./run.sh`, without the setup steps. |
| `npm run mock` | Starts four fake WLED devices on 127.0.0.1:9101–9104. Run it in its own terminal. |
| `npm run dev` | Starts the API on port 8790 and the web client with hot reload on port 5790. Open http://localhost:5790. Set `WEB_PORT` or `PORT` in `.env` to change the ports. |
| `npm run check` | Runs the typecheck, the tests and the production build. |

| Part | Stack | Folder |
|---|---|---|
| Server | Node.js 24 (runs TypeScript directly), Hono, better-sqlite3, Zod | [server/src](server/src) |
| Web client | React 19, Vite, Tailwind CSS 4, TanStack Query, React Router | [web/src](web/src) |
| Shared types | TypeScript | [shared/types.ts](shared/types.ts) |
| Tests | Vitest, against fake WLED devices | [server/test](server/test) |

Live updates use server-sent events: the server checks every device on a timer and pushes changes to open pages.

## Release

Push a tag such as `v2.0.0`. The workflow in [.github/workflows](.github/workflows) runs the checks and publishes a multi-arch image (amd64, arm64) to GHCR.
