// Links straight to a game or a scene, to share or put on a sign: /play/<game> starts the game
// (or offers it when the lights are busy), /scene/<name> plays the scene (or joins the line).

/** A name as it reads in a link: lower case, words joined by dashes ("Candy Cane!" → "candy-cane"). */
export function slug(name: string): string {
  return name
    .normalize('NFKD')
    .replace(/[\u0300-\u036f]/g, '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '');
}

/** The path that opens a game on the play page. */
export const gamePath = (id: string) => `/play/${encodeURIComponent(id)}`;

/**
 * The path that plays a scene: by its name when no other scene has the same one (a link that
 * reads well), else by its id.
 */
export function scenePath(scene: { id: string; name: string }, scenes: readonly { id: string; name: string }[]): string {
  const s = slug(scene.name);
  const unique = s && !scenes.some((o) => o.id !== scene.id && slug(o.name) === s);
  return `/scene/${encodeURIComponent(unique ? s : scene.id)}`;
}

/** The scene a link names: by id, else by name (see scenePath). */
export function findScene<T extends { id: string; name: string }>(ref: string, scenes: readonly T[]): T | undefined {
  const byId = scenes.find((s) => s.id === ref);
  if (byId) return byId;
  const s = slug(ref);
  return s ? scenes.find((x) => slug(x.name) === s) : undefined;
}
