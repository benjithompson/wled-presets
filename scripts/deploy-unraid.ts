// Updates the live site on Unraid to the latest image, through the Unraid API (GraphQL), as
// the Docker tab's "apply update" does, then waits until it runs again and checks its version.
//
//   node scripts/deploy-unraid.ts            update, then expect the version in package.json
//   node scripts/deploy-unraid.ts 2.41.0     update, then expect this version
//   node scripts/deploy-unraid.ts --check    only show what runs now (changes nothing)
//
// Needs, both kept out of git: unraid/unraid-api-key.txt (an Unraid API key with Docker access)
// and unraid/unraid-url.txt (the server's API address, for example https://192.168.1.2:443).
// UNRAID_API_KEY and UNRAID_URL in the environment win over the files. Unraid's certificate is
// self-signed, so it is not checked: use this on the home network only.

import { readFileSync } from 'node:fs';
import { request } from 'node:https';

const CONTAINER = 'wled-presets';
const root = new URL('..', import.meta.url);
const read = (file: string) => {
  try {
    return readFileSync(new URL(file, root), 'utf8').trim();
  } catch {
    return '';
  }
};
const key = process.env.UNRAID_API_KEY || read('unraid/unraid-api-key.txt');
const base = (process.env.UNRAID_URL || read('unraid/unraid-url.txt')).replace(/\/+$/, '');
if (!key || !base) {
  console.error('Put the API key in unraid/unraid-api-key.txt and the address in unraid/unraid-url.txt (or set UNRAID_API_KEY and UNRAID_URL).');
  process.exit(2);
}
const arg = process.argv[2];
const checkOnly = arg === '--check';
const expected = checkOnly ? null : arg || (JSON.parse(read('package.json')) as { version: string }).version;

/** One GraphQL call. The update can take minutes (it pulls the image). */
function gql<T>(query: string, variables: Record<string, unknown> = {}, timeoutMs = 30_000): Promise<T> {
  const body = JSON.stringify({ query, variables });
  const url = new URL(`${base}/graphql`);
  return new Promise((resolve, reject) => {
    const req = request(
      url,
      { method: 'POST', rejectUnauthorized: false, timeout: timeoutMs, headers: { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body), 'x-api-key': key } },
      (res) => {
        let text = '';
        res.on('data', (c) => (text += c));
        res.on('end', () => {
          try {
            const out = JSON.parse(text) as { data?: T; errors?: { message: string }[] };
            if (out.errors?.length) reject(new Error(out.errors.map((e) => e.message).join('; ')));
            else resolve(out.data as T);
          } catch {
            reject(new Error(`HTTP ${res.statusCode}: ${text.slice(0, 200)}`));
          }
        });
      }
    );
    req.on('timeout', () => req.destroy(new Error('Unraid did not answer in time')));
    req.on('error', reject);
    req.end(body);
  });
}

interface Container {
  id: string;
  names: string[];
  state: string;
  status: string;
  labels: Record<string, string> | null;
}

async function find(): Promise<Container> {
  const d = await gql<{ docker: { containers: Container[] } }>('{ docker { containers { id names state status labels } } }');
  const c = d.docker.containers.find((x) => x.names.some((n) => n.replace(/^\//, '') === CONTAINER));
  if (!c) throw new Error(`No container named ${CONTAINER} on Unraid`);
  return c;
}

const version = (c: Container) => c.labels?.['org.opencontainers.image.version'] ?? '?';
const show = (c: Container) => `${CONTAINER} ${version(c)} (${c.labels?.['org.opencontainers.image.revision']?.slice(0, 7) ?? '?'}), ${c.state.toLowerCase()}: ${c.status}`;

const before = await find();
console.log(`Now: ${show(before)}`);
if (checkOnly) {
  const s = await gql<{ docker: { containerUpdateStatuses: { name: string; updateStatus: string }[] } }>('{ docker { containerUpdateStatuses { name updateStatus } } }');
  console.log(`Unraid's last update check: ${s.docker.containerUpdateStatuses.find((x) => x.name === CONTAINER)?.updateStatus ?? 'unknown'}`);
  process.exit(0);
}

console.log('Updating (pulling the latest image and recreating the container)…');
await gql('mutation ($id: PrefixedID!) { docker { updateContainer(id: $id) { id } } }', { id: before.id }, 10 * 60_000);

// The container comes back with a new id; wait until it runs and is healthy.
const until = Date.now() + 3 * 60_000;
let now = await find().catch(() => null);
while (Date.now() < until && !(now && now.state === 'RUNNING' && /healthy/.test(now.status) && !/unhealthy|starting/.test(now.status))) {
  await new Promise((r) => setTimeout(r, 3000));
  now = await find().catch(() => null);
}
if (!now) throw new Error('The container did not come back');
console.log(`After: ${show(now)}`);
if (expected && version(now) !== expected) {
  console.error(`Expected ${expected}, but ${version(now)} runs. Is the image for ${expected} published yet (the "CI and Docker" run)?`);
  process.exit(1);
}
if (now.state !== 'RUNNING') process.exit(1);
console.log(expected ? `Done: ${expected} runs.` : 'Done.');
