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

/**
 * A time soon, as people say it: "4:33 PM" (or with `at`, "at 4:33 PM"), "tomorrow at 7:02 AM",
 * "Friday at 4:33 PM". In the time zone given, else the viewer's own.
 */
export function soonTime(iso: string | number, { timeZone, now = Date.now(), at: prefix = false }: { timeZone?: string; now?: number; at?: boolean } = {}): string {
  const at = new Date(iso);
  const day = (d: Date | number) => new Intl.DateTimeFormat('en-CA', { timeZone, year: 'numeric', month: '2-digit', day: '2-digit' }).format(d);
  const time = at.toLocaleTimeString(undefined, { timeZone, hour: 'numeric', minute: '2-digit' });
  const days = Math.round((Date.parse(day(at)) - Date.parse(day(now))) / 86_400_000);
  if (days === 0) return prefix ? `at ${time}` : time;
  if (days === 1) return `tomorrow at ${time}`;
  if (days > 1 && days < 7) return `${at.toLocaleDateString(undefined, { timeZone, weekday: 'long' })} at ${time}`;
  return `${at.toLocaleDateString(undefined, { timeZone, month: 'short', day: 'numeric' })} at ${time}`;
}
