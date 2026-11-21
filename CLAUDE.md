# CLAUDE.md

## How the live site runs

- Docker on Unraid, image `ghcr.io/benjithompson/wled-presets:latest` (template: [unraid/wled-presets.xml](unraid/wled-presets.xml)), container `wled-presets`.
- **Deploying** (after a merge, once the "CI and Docker" run has passed): `node scripts/deploy-unraid.ts` ([scripts/deploy-unraid.ts](scripts/deploy-unraid.ts)). It asks the Unraid API (GraphQL, `docker.updateContainer`) to pull the new image and recreate the container, waits until it is healthy, and checks that the running image's version label matches `package.json` (or the version passed as an argument). `--check` only shows what runs now. It needs `unraid/unraid-api-key.txt` and `unraid/unraid-url.txt` (the API address on the LAN), both gitignored: never commit or print them. Unraid's certificate is self-signed; the script talks to it on the LAN only. It runs outside the sandbox (LAN access). By hand instead: Docker tab → Check for Updates → apply update.
- **Behind nginx with HTTPS, `TRUST_PROXY=1`.** Visitors' addresses come from the last `X-Forwarded-For` entry nginx adds ([server/src/clientIp.ts](server/src/clientIp.ts)). No Cloudflare tunnel: don't suggest `TRUST_PROXY=cloudflare`.
- HTTPS at a domain name means passkeys work on the public address. On the plain-HTTP LAN address (an IP and port) they don't, and the password still works there.
- The site is open to the internet: assume strangers use it at the same time, and some will abuse it. Public actions that touch the lights go through the line ([server/src/line.ts](server/src/line.ts)) and need rate limits.

## Checks

`npm run check` runs typecheck, tests (vitest) and build. Run it before every commit.

## Pull requests and releases

- Work on a branch and open a PR to `main`. The user merges, squash-merging.
- **Every PR bumps `version` in `package.json`** (minor for features, patch for fixes) and uses that version in its title (`v2.22.0: …`).
- Merging is the release. CI ([.github/workflows/docker-publish.yml](.github/workflows/docker-publish.yml)) runs the checks, tags the merge `vX.Y.Z`, makes a GitHub release and publishes the Docker image (`latest`, `X.Y.Z`, `X.Y`, `X`). Don't tag by hand. After a merge, check that the "CI and Docker" run passed, then deploy it (see above).
