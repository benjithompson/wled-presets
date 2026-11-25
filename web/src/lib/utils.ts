import { clsx, type ClassValue } from 'clsx';
import { toast } from 'sonner';

export const cn = (...v: ClassValue[]) => clsx(v);

const rtf = new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' });

export function relativeTime(iso: string, now = Date.now()): string {
  const diff = (new Date(iso).getTime() - now) / 1000;
  const abs = Math.abs(diff);
  if (abs < 45) return rtf.format(Math.round(diff), 'second');
  if (abs < 2700) return rtf.format(Math.round(diff / 60), 'minute');
  if (abs < 64800) return rtf.format(Math.round(diff / 3600), 'hour');
  return rtf.format(Math.round(diff / 86400), 'day');
}

export function errorText(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

export function downloadJson(data: unknown, filename: string) {
  const url = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' }));
  const a = Object.assign(document.createElement('a'), { href: url, download: filename });
  document.body.append(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

/**
 * Copies a link to a page of this site (a path such as /play/cascade) and says so. The clipboard
 * API needs HTTPS; on the plain-HTTP LAN address the older way is tried, and failing that the
 * link is shown to copy by hand.
 */
export async function copyLink(path: string, what = 'Link'): Promise<void> {
  const url = new URL(path, location.origin).href;
  let copied = false;
  try {
    await navigator.clipboard.writeText(url);
    copied = true;
  } catch {
    const box = document.createElement('textarea');
    box.value = url;
    box.setAttribute('readonly', '');
    box.style.cssText = 'position:fixed;opacity:0;pointer-events:none';
    document.body.append(box);
    box.select();
    try {
      copied = document.execCommand('copy');
    } catch {
      /* shown instead */
    }
    box.remove();
  }
  if (copied) toast.success(`${what} copied`, { description: url });
  else toast.info(url, { description: 'Copy this link to share it', duration: 15_000 });
}
