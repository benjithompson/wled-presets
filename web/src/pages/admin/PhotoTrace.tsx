// A custom object from a photo: light the object's LEDs in a color that stands out (the first
// LED in another), take a picture, and the lit LEDs become dots in the order the wire runs. When
// that goes wrong, or the LEDs are too close together to tell apart, trace the wire by hand:
// drag through the dots (or along the wire) with the mouse or a finger. The photo stays in this
// browser; only the colors for the lights go to the server.
import { useEffect, useMemo, useRef, useState, type PointerEvent as RPointerEvent, type ReactNode, type WheelEvent as RWheelEvent } from 'react';
import { Camera, CircleDot, Flag, Hand, ImagePlus, Lightbulb, Maximize, Route, ScanLine, Undo2, WandSparkles, X } from 'lucide-react';
import { deviceLed, FEET_PER_METER, MAX_FIXTURE_PIXELS, type DesignStroke, type Layout } from '../../../../shared/layout.ts';
import {
  autoDots,
  codeFrames,
  colorfulMaps,
  decodeScan,
  findDots,
  glowMaps,
  isLoop,
  ledStep,
  orderByNumber,
  orderDots,
  PHOTO_COLORS,
  photoDesign,
  photoWidth,
  simplify,
  THRESHOLDS,
  traceDots,
  typicalGap,
  type GlowMaps,
  type PhotoStroke,
  type Pt
} from '../../../../shared/photoTrace.ts';
import { Button, Dialog, Switch } from '../../components/ui.tsx';
import { api } from '../../lib/api.ts';
import { useInFront } from '../../lib/useInFront.ts';
import { cn } from '../../lib/utils.ts';
import { useOverview } from './AdminLayout.tsx';
import { PropNote, PropNumber, PropRow, PropSection, PropSelect } from './props.tsx';

/** The photo, made smaller: big enough to see each LED, small enough to look through quickly. */
const MAX_SIDE = 1400;

type Tool = 'connect' | 'dots' | 'start' | 'move';
/** A dot in the photo. `num`: its LED number, when a scan read it. */
type Dot = Pt & { id: number; num?: number };
/** A run of the wire traced by hand: through dots (by id), or freehand where no dots were found. */
type Run = { ids: number[]; closed?: boolean } | { free: Pt[] };

interface Photo {
  url: string;
  width: number;
  height: number;
  maps: (color: (typeof PHOTO_COLORS)[number]) => GlowMaps;
  /** How many LEDs were lit for it, when this page lit them. */
  lit: number | null;
  /** From a camera scan: how many LEDs it read the numbers of. */
  scanned?: number;
}

interface Snapshot {
  dots: Dot[];
  runs: Run[] | null;
  startId: number | null;
}

export function PhotoTrace({
  open,
  layout,
  designId,
  pixels,
  spacing,
  onUse,
  onLights,
  onClose
}: {
  open: boolean;
  layout: Layout;
  /** The design being made: objects placed from it tell which LEDs to light. */
  designId: string;
  /** How many LEDs the design has now. */
  pixels: number;
  /** Meters from one LED to the next on its light string, when known: it sizes the shape. */
  spacing: number | null;
  /** The traced shape, and its number of LEDs (null: fit them to the wire). */
  onUse: (strokes: DesignStroke[], pixels: number | null) => void;
  /** True while this lights the object (the layout editor's own preview waits). */
  onLights: (on: boolean) => void;
  onClose: () => void;
}) {
  const units = layout.units ?? 'ft';
  const perUnit = units === 'm' ? 1 : 1 / FEET_PER_METER;

  // ----- Lighting the object -----
  const { data: overview } = useOverview();
  const devices = overview?.devices ?? [];
  const placed = layout.fixtures.find((f) => f.designId === designId && f.deviceId);
  const [deviceId, setDeviceId] = useState('');
  const [from, setFrom] = useState(0);
  const [to, setTo] = useState(Math.max(0, pixels - 1));
  const [colorId, setColorId] = useState(PHOTO_COLORS[0].id);
  const [lightUp, setLightUp] = useState(false);
  const color = PHOTO_COLORS.find((c) => c.id === colorId) ?? PHOTO_COLORS[0];
  const count = Math.abs(to - from) + 1;

  // Which LEDs: those of an object placed from this design, else the next free ones on a device.
  useEffect(() => {
    if (!open) return;
    if (placed) {
      setDeviceId(placed.deviceId!);
      setFrom(deviceLed(placed, 0));
      setTo(deviceLed(placed, Math.max(0, placed.pixels - 1)));
    } else {
      const id = layout.fixtures.at(-1)?.deviceId ?? devices[0]?.id ?? '';
      const next = Math.max(0, ...layout.fixtures.filter((f) => f.deviceId === id).map((f) => f.startPixel + f.pixels));
      setDeviceId(id);
      setFrom(next);
      setTo(next + Math.max(0, pixels - 1));
    }
    setLightUp(false);
    // Only when it opens: later the fields are the user's.
  }, [open]);
  useEffect(() => {
    if (!deviceId && devices[0]) setDeviceId(devices[0].id);
  }, [deviceId, devices]);

  const inFront = useInFront();
  const lighting = open && lightUp && !!deviceId && count <= MAX_FIXTURE_PIXELS && inFront;
  /** While scanning: the frame the lights show (see codeDigit). */
  const [scanCode, setScanCode] = useState<number | null>(null);
  const lightBody = lighting ? JSON.stringify({ active: true, layout, selected: null, corner: null, photo: { deviceId, from, to, rgb: color.rgb, start: color.start, code: scanCode } }) : null;
  useEffect(() => {
    onLights(lighting);
    return () => onLights(false);
  }, [lighting]);
  useEffect(() => {
    if (!lightBody) return;
    // After the layout editor has stopped its own preview.
    const t = setTimeout(() => void api.previewLayout(lightBody).catch(() => {}), 150);
    const keep = setInterval(() => void api.previewLayout(lightBody).catch(() => {}), 3000);
    return () => {
      clearTimeout(t);
      clearInterval(keep);
    };
  }, [lightBody]);
  useEffect(() => {
    if (!lighting) return;
    const stop = () => void api.stopLayoutPreview().catch(() => {});
    window.addEventListener('pagehide', stop);
    return () => {
      window.removeEventListener('pagehide', stop);
      stop();
    };
  }, [lighting]);

  // ----- The photo and the dots in it -----
  const [photo, setPhoto] = useState<Photo | null>(null);
  const [loading, setLoading] = useState(false);
  const [problem, setProblem] = useState<string | null>(null);
  const [level, setLevel] = useState<number | null>(null);
  const [dots, setDots] = useState<Dot[]>([]);
  const [startId, setStartId] = useState<number | null>(null);
  /** Null: the order is worked out from the dots. */
  const [runs, setRuns] = useState<Run[] | null>(null);
  const [tool, setTool] = useState<Tool>('connect');
  const [widthM, setWidthM] = useState<number | null>(null);
  const past = useRef<Snapshot[]>([]);
  const nextId = useRef(1);
  const [, tick] = useState(0);
  const cameraInput = useRef<HTMLInputElement>(null);
  const fileInput = useRef<HTMLInputElement>(null);

  useEffect(() => () => void (photo && URL.revokeObjectURL(photo.url)), [photo]);
  useEffect(() => {
    if (open) return;
    closeCamera();
    setPhoto(null);
    setDots([]);
    setRuns(null);
    setStartId(null);
    setWidthM(null);
    setProblem(null);
    past.current = [];
  }, [open]);

  const remember = () => {
    past.current.push({ dots, runs, startId });
    if (past.current.length > 60) past.current.shift();
    tick((n) => n + 1);
  };
  const undo = () => {
    const s = past.current.pop();
    if (!s) return;
    setDots(s.dots);
    setRuns(s.runs);
    setStartId(s.startId);
    tick((n) => n + 1);
  };

  /** Finds the dots again (another color or sensitivity): hand-made changes start over. */
  const detect = (p: Photo, threshold: number | null) => {
    const maps = p.maps(color);
    const found = threshold == null ? autoDots(maps, p.lit) : { dots: findDots(maps, threshold), threshold };
    const list = found.dots.map((d) => ({ x: d.x, y: d.y, id: nextId.current++, start: d.start }));
    setLevel(THRESHOLDS.indexOf(found.threshold));
    setDots(list.map(({ x, y, id }) => ({ x, y, id })));
    setStartId(list.find((d) => d.start)?.id ?? null);
    setRuns(null);
    past.current = [];
    setView(null);
  };

  const load = async (file: File | undefined) => {
    if (!file) return;
    setLoading(true);
    setProblem(null);
    try {
      const bmp = await createImageBitmap(file, { imageOrientation: 'from-image' });
      const k = Math.min(1, MAX_SIDE / Math.max(bmp.width, bmp.height));
      const width = Math.max(1, Math.round(bmp.width * k));
      const height = Math.max(1, Math.round(bmp.height * k));
      const canvas = document.createElement('canvas');
      canvas.width = width;
      canvas.height = height;
      const ctx = canvas.getContext('2d', { willReadFrequently: true })!;
      ctx.drawImage(bmp, 0, 0, width, height);
      bmp.close();
      const pixels = ctx.getImageData(0, 0, width, height);
      const blob = await new Promise<Blob | null>((r) => canvas.toBlob(r, 'image/jpeg', 0.9));
      if (!blob) throw new Error('no picture');
      const cache = new Map<string, GlowMaps>();
      const p: Photo = {
        url: URL.createObjectURL(blob),
        width,
        height,
        maps: (c) => cache.get(c.id) ?? (cache.set(c.id, glowMaps(pixels, c)), cache.get(c.id)!),
        lit: lighting ? count : null
      };
      setPhoto(p);
      setWidthM(null);
      // Let the spinner show: looking through a big photo takes a moment.
      await new Promise((r) => setTimeout(r, 30));
      detect(p, null);
    } catch (e) {
      console.error('Photo', e);
      setProblem('That picture could not be opened. Try a JPEG or PNG.');
    } finally {
      setLoading(false);
    }
  };

  // Another color: look again (a scan's dots stay: they have their numbers).
  useEffect(() => {
    if (photo && !photo.scanned) detect(photo, null);
  }, [colorId]);

  // ----- Scanning with the camera: the LEDs blink their numbers in color -----
  const video = useRef<HTMLVideoElement>(null);
  const [camera, setCamera] = useState<MediaStream | null>(null);
  const [scanning, setScanning] = useState<{ frame: number; of: number } | null>(null);
  const cancelScan = useRef(false);
  const canScan = typeof navigator !== 'undefined' && !!navigator.mediaDevices?.getUserMedia && window.isSecureContext && !!deviceId && count <= MAX_FIXTURE_PIXELS;
  const frames = codeFrames(count);

  const openCamera = async () => {
    setProblem(null);
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: { ideal: 'environment' }, width: { ideal: 1920 }, height: { ideal: 1080 } }, audio: false });
      setCamera(stream);
      setLightUp(true);
    } catch {
      setProblem('The camera could not be opened. Allow it for this site in the browser, or take a photo instead.');
    }
  };
  function closeCamera() {
    cancelScan.current = true;
    setCamera((c) => {
      c?.getTracks().forEach((t) => t.stop());
      return null;
    });
    setScanning(null);
    setScanCode(null);
  }
  useEffect(() => {
    if (video.current && camera) video.current.srcObject = camera;
  }, [camera]);
  useEffect(() => () => camera?.getTracks().forEach((t) => t.stop()), [camera]);

  /** The camera's picture now, made smaller like a photo. */
  const grab = () => {
    const v = video.current!;
    const k = Math.min(1, MAX_SIDE / Math.max(v.videoWidth, v.videoHeight));
    const canvas = document.createElement('canvas');
    canvas.width = Math.max(1, Math.round(v.videoWidth * k));
    canvas.height = Math.max(1, Math.round(v.videoHeight * k));
    const ctx = canvas.getContext('2d', { willReadFrequently: true })!;
    ctx.drawImage(v, 0, 0, canvas.width, canvas.height);
    return { canvas, pixels: ctx.getImageData(0, 0, canvas.width, canvas.height) };
  };

  /**
   * Shows each frame of the code on the lights, takes the camera's picture of it, and reads
   * every LED's number from its colors: the dots come out in the wire's exact order.
   */
  const runScan = async () => {
    if (!video.current?.videoWidth) return;
    const n = count;
    const body = (code: number) => ({ active: true as const, layout, selected: null, corner: null, photo: { deviceId, from, to, rgb: color.rgb, start: color.start, code } });
    cancelScan.current = false;
    setProblem(null);
    const shots: { canvas: HTMLCanvasElement; pixels: ImageData }[] = [];
    try {
      for (let f = 0; f < frames; f++) {
        setScanning({ frame: f + 1, of: frames });
        setScanCode(f);
        await api.previewLayout(JSON.stringify(body(f)));
        // The lights change, then the camera sees it (and settles its exposure on the first frame).
        await new Promise((r) => setTimeout(r, f === 0 ? 900 : 500));
        if (cancelScan.current) return;
        shots.push(grab());
      }
    } catch {
      setProblem('The lights did not answer. Try again.');
      return;
    } finally {
      setScanCode(null);
      setScanning(null);
    }
    const first = colorfulMaps(shots[0].pixels);
    const found = autoDots(first, n);
    const nums = decodeScan(
      shots.map((s) => s.pixels),
      found.dots,
      n,
      found.threshold
    );
    const order = orderByNumber(found.dots, nums);
    const read = nums.filter((x) => x != null).length;
    const blob = await new Promise<Blob | null>((r) => shots[0].canvas.toBlob(r, 'image/jpeg', 0.9));
    if (!blob) return;
    const cache = new Map<string, GlowMaps>();
    const pixels = shots[0].pixels;
    closeCamera();
    setPhoto({
      url: URL.createObjectURL(blob),
      width: pixels.width,
      height: pixels.height,
      maps: (c) => cache.get(c.id) ?? (cache.set(c.id, glowMaps(pixels, c)), cache.get(c.id)!),
      lit: n,
      scanned: read
    });
    const list: Dot[] = found.dots.map((d, k) => ({ x: d.x, y: d.y, id: nextId.current++, ...(nums[k] != null ? { num: nums[k]! } : {}) }));
    setDots(list);
    setRuns(order.map((o) => ({ ids: o.map((k) => list[k].id), ...(isLoop(o.map((k) => list[k]), typicalGap(list)) && nums[o[0]] === 0 && nums[o.at(-1)!] === n - 1 ? { closed: true } : {}) })));
    setStartId(list.find((d) => d.num === 0)?.id ?? null);
    past.current = [];
    setWidthM(null);
    setView(null);
    setTool('connect');
    if (read < Math.max(2, found.dots.length * 0.5))
      setProblem(`Only ${read} of ${found.dots.length} LEDs could be read. Hold the phone still (rest it on something), keep the whole object in view, and scan again; or fix the order by hand.`);
  };

  // ----- The wire through the dots -----
  const byId = useMemo(() => new Map(dots.map((d) => [d.id, d])), [dots]);
  const autoRuns = useMemo<Run[]>(() => {
    if (runs || !dots.length) return [];
    const start = dots.findIndex((d) => d.id === startId);
    const gap = typicalGap(dots);
    return orderDots(dots, start >= 0 ? start : null).map((o) => {
      const ids = o.map((i) => dots[i].id);
      return { ids, ...(isLoop(o.map((i) => dots[i]), gap) ? { closed: true } : {}) };
    });
  }, [dots, startId, runs]);
  const wire = runs ?? autoRuns;
  const strokes: PhotoStroke[] = wire
    .map((r): PhotoStroke => ('free' in r ? { points: r.free, dots: false } : { points: r.ids.map((id) => byId.get(id)).filter((d): d is Dot => !!d), dots: true, closed: r.closed }))
    .filter((s) => s.points.length);
  const used = new Set(wire.flatMap((r) => ('ids' in r ? r.ids : [])));
  const loose = dots.filter((d) => !used.has(d.id)).length;

  const step = ledStep(strokes);
  const widthPx = photoWidth(strokes);
  const fromSpacing = spacing && step > 0 ? spacing / step : null;
  const metersPerPixel = widthM && widthPx > 0 ? widthM / widthPx : (fromSpacing ?? (widthPx > 0 ? 1 / widthPx : 0));
  const shownWidth = widthPx * metersPerPixel;
  const allDots = strokes.length > 0 && strokes.every((s) => s.dots);
  const ledCount = photo?.lit ?? (allDots ? strokes.reduce((a, s) => a + s.points.length, 0) : null);

  const use = () => {
    const design = photoDesign(strokes, metersPerPixel);
    if (design.length) onUse(design, ledCount);
  };

  // ----- The view: photo pixels to screen pixels -----
  const wrap = useRef<HTMLDivElement>(null);
  const [size, setSize] = useState({ w: 600, h: 400 });
  useEffect(() => {
    const el = wrap.current;
    if (!el) return;
    const ro = new ResizeObserver(([e]) => setSize({ w: Math.max(200, e.contentRect.width), h: Math.max(200, e.contentRect.height) }));
    ro.observe(el);
    return () => ro.disconnect();
  }, [open, photo]);
  const [view, setView] = useState<{ x: number; y: number; k: number } | null>(null);
  const fit = () => {
    if (!photo) return { x: 0, y: 0, k: 1 };
    const k = Math.min(size.w / photo.width, size.h / photo.height);
    return { x: (size.w - photo.width * k) / 2, y: (size.h - photo.height * k) / 2, k };
  };
  const v = view ?? fit();
  const S = (p: Pt) => ({ X: v.x + p.x * v.k, Y: v.y + p.y * v.k });
  const I = (X: number, Y: number): Pt => ({ x: (X - v.x) / v.k, y: (Y - v.y) / v.k });
  const zoomAt = (X: number, Y: number, f: number, from = v) => {
    const k = Math.min(Math.max(from.k * f, fit().k * 0.5), 12);
    return { k, x: X - ((X - from.x) / from.k) * k, y: Y - ((Y - from.y) / from.k) * k };
  };

  const local = (e: { clientX: number; clientY: number }) => {
    const r = wrap.current!.getBoundingClientRect();
    return { X: e.clientX - r.left, Y: e.clientY - r.top };
  };
  const nearestDot = (X: number, Y: number, within = 16): Dot | null => {
    let best: Dot | null = null;
    let bd = within;
    for (const d of dots) {
      const q = S(d);
      const dd = Math.hypot(q.X - X, q.Y - Y);
      if (dd < bd) {
        bd = dd;
        best = d;
      }
    }
    return best;
  };

  // Pointers: one traces, taps or pans (with the tool); two pinch to zoom and pan.
  const pointers = useRef(new Map<number, { X: number; Y: number }>());
  const gesture = useRef<
    | { kind: 'trace'; path: Pt[] }
    | { kind: 'tap'; X: number; Y: number; moved: boolean }
    | { kind: 'pan'; X: number; Y: number; from: typeof v }
    | { kind: 'pinch'; d: number; mid: { X: number; Y: number }; from: typeof v }
    | null
  >(null);
  const [tracePath, setTracePath] = useState<Pt[] | null>(null);

  const onDown = (e: RPointerEvent<HTMLDivElement>) => {
    if (!photo) return;
    const p = local(e);
    pointers.current.set(e.pointerId, p);
    try {
      e.currentTarget.setPointerCapture(e.pointerId);
    } catch {}
    if (pointers.current.size === 2) {
      const [a, b] = [...pointers.current.values()];
      gesture.current = { kind: 'pinch', d: Math.hypot(a.X - b.X, a.Y - b.Y), mid: { X: (a.X + b.X) / 2, Y: (a.Y + b.Y) / 2 }, from: v };
      setTracePath(null);
      return;
    }
    if (pointers.current.size > 2) return;
    if (e.button === 1 || e.button === 2 || tool === 'move' || (e.pointerType === 'mouse' && e.shiftKey)) gesture.current = { kind: 'pan', X: p.X, Y: p.Y, from: v };
    else if (tool === 'connect') {
      gesture.current = { kind: 'trace', path: [I(p.X, p.Y)] };
      setTracePath([I(p.X, p.Y)]);
    } else gesture.current = { kind: 'tap', X: p.X, Y: p.Y, moved: false };
  };
  const onMove = (e: RPointerEvent<HTMLDivElement>) => {
    if (!pointers.current.has(e.pointerId)) return;
    const p = local(e);
    pointers.current.set(e.pointerId, p);
    const g = gesture.current;
    if (!g) return;
    if (g.kind === 'pinch' && pointers.current.size >= 2) {
      const [a, b] = [...pointers.current.values()];
      const d = Math.hypot(a.X - b.X, a.Y - b.Y);
      const mid = { X: (a.X + b.X) / 2, Y: (a.Y + b.Y) / 2 };
      const z = zoomAt(g.mid.X, g.mid.Y, d / Math.max(1, g.d), g.from);
      setView({ k: z.k, x: z.x + mid.X - g.mid.X, y: z.y + mid.Y - g.mid.Y });
    } else if (g.kind === 'pan') setView({ ...g.from, x: g.from.x + p.X - g.X, y: g.from.y + p.Y - g.Y });
    else if (g.kind === 'trace') {
      const q = I(p.X, p.Y);
      const last = g.path.at(-1)!;
      if (Math.hypot(q.x - last.x, q.y - last.y) * v.k >= 2) {
        g.path.push(q);
        setTracePath([...g.path]);
      }
    } else if (g.kind === 'tap' && Math.hypot(p.X - g.X, p.Y - g.Y) > 8) g.moved = true;
  };
  const onUp = (e: RPointerEvent<HTMLDivElement>) => {
    if (!pointers.current.delete(e.pointerId)) return;
    const g = gesture.current;
    // After a pinch, the finger still down does nothing until it lifts.
    gesture.current = null;
    if (g?.kind === 'pinch') return;
    if (!g) return;
    if (g.kind === 'trace') {
      setTracePath(null);
      if (e.type === 'pointercancel') return;
      finishTrace(g.path);
    } else if (g.kind === 'tap' && !g.moved && e.type !== 'pointercancel') {
      const p = local(e);
      if (tool === 'dots') toggleDot(p.X, p.Y);
      else if (tool === 'start') {
        const d = nearestDot(p.X, p.Y, 24);
        if (d) {
          remember();
          setStartId(d.id);
          setRuns(null);
        }
      }
    }
  };
  const onWheel = (e: RWheelEvent<HTMLDivElement>) => {
    if (!photo) return;
    const p = local(e);
    setView(zoomAt(p.X, p.Y, Math.exp(-e.deltaY * 0.0015)));
  };

  /** A traced run: through the dots it passed, or (none there) along the path itself. */
  const finishTrace = (path: Pt[]) => {
    const radius = 14 / v.k;
    const taken = new Set(runs ? runs.flatMap((r) => ('ids' in r ? r.ids : [])) : []);
    const idx = traceDots(dots, path, radius, new Set(dots.map((d, i) => (taken.has(d.id) ? i : -1)).filter((i) => i >= 0)));
    let run: Run | null = null;
    if (idx.length >= 2) {
      const pts = idx.map((i) => dots[i]);
      const gap = typicalGap(dots);
      // Back to where it started: the wire goes all round.
      const end = path.at(-1)!;
      const round = isLoop(pts, gap) && Math.hypot(end.x - pts[0].x, end.y - pts[0].y) <= Math.max(radius, gap * 1.8);
      run = { ids: idx.map((i) => dots[i].id), ...(round ? { closed: true } : {}) };
    } else {
      const len = path.slice(1).reduce((a, p, i) => a + Math.hypot(p.x - path[i].x, p.y - path[i].y), 0);
      if (len * v.k >= 12) run = { free: simplify(path, 1.5 / v.k) };
    }
    if (!run) return;
    remember();
    // The first run traced by hand replaces the worked-out order.
    setRuns((r) => [...(r ?? []), run]);
  };

  const toggleDot = (X: number, Y: number) => {
    remember();
    const d = nearestDot(X, Y, 12);
    if (d) {
      setDots((list) => list.filter((x) => x.id !== d.id));
      setRuns((r) => r && r.map((x) => ('ids' in x ? { ...x, ids: x.ids.filter((id) => id !== d.id) } : x)).filter((x) => ('ids' in x ? x.ids.length : true)));
      if (startId === d.id) setStartId(null);
    } else setDots((list) => [...list, { ...I(X, Y), id: nextId.current++ }]);
  };

  // ----- Drawing -----
  const toolBtn = (t: Tool, label: string, Icon: typeof Hand, title: string) => (
    <button
      type="button"
      onClick={() => setTool(t)}
      title={title}
      aria-pressed={tool === t}
      className={cn('flex h-8 items-center gap-1.5 rounded-lg px-2.5 text-xs font-medium transition [&_svg]:size-4', tool === t ? 'bg-sky-600 text-white' : 'text-stone-700 hover:bg-stone-200/70 dark:text-stone-300 dark:hover:bg-stone-800')}
    >
      <Icon /> {label}
    </button>
  );
  const dotR = Math.max(2.5, Math.min(7, (step || typicalGap(dots) || 10) * v.k * 0.28));
  const ledIndex = new Map<number, number>();
  {
    let n = 0;
    for (const r of wire) if ('ids' in r) for (const id of r.ids) if (byId.has(id)) ledIndex.set(id, n++);
  }
  const firstId = wire.find((r): r is { ids: number[] } => 'ids' in r && r.ids.length > 0)?.ids[0];

  const hint: Record<Tool, ReactNode> = {
    connect: runs
      ? 'Drag through the lights in the order the wire runs. Lift where the wire jumps, and go on from where it lands. No lights found? Drag along the wire.'
      : 'Wrong order? Drag through the lights from the first LED, the way the wire runs: that replaces the order.',
    dots: 'Tap a dot to remove it (not an LED), or tap where an LED was missed to add one.',
    start: 'Tap the dot where the wire starts (LED 0).',
    move: 'Drag to move the photo; wheel or pinch to zoom.'
  };

  return (
    <Dialog
      open={open}
      onClose={onClose}
      size="xl"
      title="Custom object from a photo"
      description="Light the object up, take a picture of it from the front, and the lit LEDs become its shape. The photo stays on this device."
      footer={
        <>
          {strokes.length ? (
            <span className="mr-auto self-center text-xs text-stone-500 tabular-nums">
              {strokes.length} stroke{strokes.length === 1 ? '' : 's'}
              {ledCount != null ? ` · ${ledCount} LEDs` : ''}
              {shownWidth > 0 ? ` · ${Math.round((shownWidth / perUnit) * 100) / 100} ${units} wide` : ''}
            </span>
          ) : null}
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" disabled={!strokes.length || !(metersPerPixel > 0)} onClick={use}>
            Use this shape
          </Button>
        </>
      }
    >
      <input ref={cameraInput} type="file" accept="image/*" capture="environment" className="hidden" onChange={(e) => (void load(e.target.files?.[0]), (e.target.value = ''))} />
      <input ref={fileInput} type="file" accept="image/*" className="hidden" onChange={(e) => (void load(e.target.files?.[0]), (e.target.value = ''))} />
      <div className="flex flex-col gap-3 pb-2 lg:flex-row">
        <div className="min-w-0 flex-1">
          <div className="mb-2 flex flex-wrap items-center gap-1">
            {toolBtn('connect', 'Connect', Route, 'Connect the dots: drag through them in wire order')}
            {toolBtn('dots', 'Dots', CircleDot, 'Add or remove dots')}
            {toolBtn('start', 'First LED', Flag, 'Pick the dot where the wire starts')}
            {toolBtn('move', 'Move', Hand, 'Move and zoom the photo')}
            <span className="mx-1 h-5 w-px bg-stone-200 dark:bg-stone-700" />
            <Button size="sm" variant="ghost" onClick={undo} disabled={!past.current.length} title="Undo" aria-label="Undo" className="px-2">
              <Undo2 />
            </Button>
            <Button size="sm" variant="ghost" onClick={() => setView(null)} title="Zoom to fit" aria-label="Zoom to fit" className="px-2">
              <Maximize />
            </Button>
            {runs ? (
              <Button size="sm" variant="ghost" onClick={() => (remember(), setRuns(null))} title="Work out the order from the dots again">
                <WandSparkles /> Automatic order
              </Button>
            ) : dots.length ? (
              <Button size="sm" variant="ghost" onClick={() => (remember(), setRuns([]), setTool('connect'))} title="Clear the order and trace the wire yourself">
                <Route /> Trace by hand
              </Button>
            ) : null}
          </div>
          <div
            ref={wrap}
            className={cn('relative h-[40dvh] min-h-64 touch-none sm:h-[52dvh] sm:min-h-72 overflow-hidden rounded-xl bg-[#05070f] select-none', photo && (tool === 'move' ? 'cursor-grab' : 'cursor-crosshair'))}
            onPointerDown={onDown}
            onPointerMove={onMove}
            onPointerUp={onUp}
            onPointerCancel={onUp}
            onWheel={onWheel}
            onContextMenu={(e) => e.preventDefault()}
          >
            {camera ? (
              <>
                <video ref={video} autoPlay playsInline muted className="absolute inset-0 size-full object-contain" />
                <div className="absolute inset-x-3 bottom-3 flex flex-wrap items-end justify-between gap-2">
                  <p className="max-w-md text-[11px] text-white/80 [text-shadow:0_1px_2px_#000]">
                    {scanning
                      ? `Reading the LEDs: frame ${scanning.frame} of ${scanning.of}. Hold still…`
                      : `Point the camera at the object, with all of it in view, and hold still (rest the phone on something). The lights change color ${frames} times, about ${Math.ceil(frames * 0.5 + 1)} seconds.`}
                  </p>
                  <div className="flex gap-2">
                    <Button size="sm" onClick={closeCamera}>
                      <X /> {scanning ? 'Stop' : 'Close camera'}
                    </Button>
                    {scanning ? null : (
                      <Button size="sm" variant="primary" onClick={() => void runScan()} disabled={!lighting}>
                        <ScanLine /> Start scan
                      </Button>
                    )}
                  </div>
                </div>
              </>
            ) : photo ? (
              <>
                <img
                  src={photo.url}
                  alt=""
                  draggable={false}
                  className="pointer-events-none absolute top-0 left-0 max-w-none origin-top-left opacity-70"
                  style={{ width: photo.width, height: photo.height, transform: `translate(${v.x}px, ${v.y}px) scale(${v.k})` }}
                />
                <svg width={size.w} height={size.h} className="pointer-events-none absolute inset-0">
                  {strokes.map((s, si) => {
                    const pts = s.closed ? [...s.points, s.points[0]] : s.points;
                    return <polyline key={si} points={pts.map((p) => `${S(p).X},${S(p).Y}`).join(' ')} fill="none" stroke={s.dots ? '#38bdf8' : '#fde68a'} strokeWidth={2} strokeLinejoin="round" strokeOpacity={0.9} />;
                  })}
                  {/* Jumps between strokes: wire without LEDs. */}
                  {strokes.slice(1).map((s, si) => {
                    const prev = strokes[si];
                    const a = prev.closed ? prev.points[0] : prev.points.at(-1)!;
                    const b = s.points[0];
                    return <line key={`j${si}`} x1={S(a).X} y1={S(a).Y} x2={S(b).X} y2={S(b).Y} stroke="#fff" strokeOpacity={0.35} strokeDasharray="3 5" />;
                  })}
                  {dots.map((d) => {
                    const q = S(d);
                    const on = used.has(d.id);
                    const first = d.id === firstId || (!wire.length && d.id === startId);
                    return (
                      <g key={d.id}>
                        <circle cx={q.X} cy={q.Y} r={dotR} fill={on ? '#fde68a' : 'none'} stroke={on ? '#05070f' : '#f87171'} strokeWidth={on ? 1 : 1.5} />
                        {first ? <circle cx={q.X} cy={q.Y} r={dotR + 5} fill="none" stroke="#22c55e" strokeWidth={2.5} /> : null}
                        {first ? (
                          <text x={q.X + dotR + 7} y={q.Y - dotR - 4} fontSize={11} fill="#86efac" stroke="#05070f" strokeWidth={3} paintOrder="stroke">
                            LED 0
                          </text>
                        ) : null}
                      </g>
                    );
                  })}
                  {/* Every tenth LED's number, to check the order. */}
                  {dots.map((d) => {
                    const n = d.num ?? ledIndex.get(d.id);
                    if (n == null || n === 0 || n % 10) return null;
                    const q = S(d);
                    return (
                      <text key={`n${d.id}`} x={q.X + dotR + 3} y={q.Y - dotR - 2} fontSize={10} fill="#fde68a" stroke="#05070f" strokeWidth={3} paintOrder="stroke" className="tabular-nums">
                        {n}
                      </text>
                    );
                  })}
                  {tracePath ? <polyline points={tracePath.map((p) => `${S(p).X},${S(p).Y}`).join(' ')} fill="none" stroke="#22c55e" strokeWidth={3} strokeOpacity={0.8} strokeLinecap="round" strokeLinejoin="round" /> : null}
                </svg>
                <p className="pointer-events-none absolute inset-x-3 bottom-2 text-[11px] text-white/70 [text-shadow:0_1px_2px_#000]">{hint[tool]} Two fingers or the wheel zoom.</p>
              </>
            ) : (
              <div className="absolute inset-0 grid place-items-center p-6 text-center text-sm text-white/70">
                <div className="max-w-sm space-y-3">
                  <Camera className="mx-auto size-8 text-white/50" />
                  <p>Take the picture in the dark or at dusk, straight from the front, with the whole object in it. Hold still.</p>
                  <div className="flex flex-wrap justify-center gap-2">
                    {canScan ? (
                      <Button variant="primary" onClick={() => void openCamera()} title="The LEDs blink their numbers in color, and the camera reads them: the exact order">
                        <ScanLine /> Scan with the camera
                      </Button>
                    ) : null}
                    <Button variant={canScan ? 'secondary' : 'primary'} loading={loading} onClick={() => cameraInput.current?.click()}>
                      <Camera /> Take a photo
                    </Button>
                    <Button onClick={() => fileInput.current?.click()} disabled={loading}>
                      <ImagePlus /> Choose a picture
                    </Button>
                  </div>
                  {problem ? <p className="text-red-300">{problem}</p> : null}
                </div>
              </div>
            )}
          </div>
        </div>

        {/* On a phone, lighting comes first until there is a photo. */}
        <div className={cn('w-full shrink-0 rounded-xl ring-1 ring-stone-200 lg:order-none lg:w-72 dark:ring-stone-800', !photo && !camera && 'order-first')}>
          <PropSection id="photo-light" title="1 · Light it up">
            {devices.length ? (
              <>
                <PropSelect label="Device" value={deviceId} options={devices.map((d): [string, string] => [d.id, d.name])} onChange={setDeviceId} />
                <PropNumber label="First LED" hint="The device's LED where the wire starts" value={from} min={0} max={10_000} steppers onChange={(n) => setFrom(Math.round(n))} />
                <PropNumber label="Last LED" hint="The device's LED where the wire ends" value={to} min={0} max={10_000} steppers onChange={(n) => setTo(Math.round(n))} />
                <PropRow label="Color">
                  <div className="flex gap-1">
                    {PHOTO_COLORS.map((c) => (
                      <button
                        key={c.id}
                        type="button"
                        title={`${c.name}, the first LED ${c.startName}`}
                        aria-label={c.name}
                        aria-pressed={c.id === colorId}
                        onClick={() => setColorId(c.id)}
                        className={cn('size-6 rounded-full ring-offset-1 ring-offset-white transition dark:ring-offset-stone-900', c.id === colorId ? 'ring-2 ring-sky-500' : 'ring-1 ring-stone-300 dark:ring-stone-600')}
                        style={{ background: `rgb(${c.rgb.map((x) => Math.min(255, x * 1.8)).join(',')})` }}
                      />
                    ))}
                  </div>
                </PropRow>
                <PropRow label="Light up now">
                  <Switch checked={lightUp} onChange={setLightUp} label="Light up now" disabled={!deviceId || count > MAX_FIXTURE_PIXELS} />
                </PropRow>
                {count > MAX_FIXTURE_PIXELS ? (
                  <PropNote tone="red">At most {MAX_FIXTURE_PIXELS} LEDs.</PropNote>
                ) : (
                  <PropNote>
                    {lighting ? <Lightbulb className="mr-1 inline size-3 text-amber-500" /> : null}
                    {count} LEDs in {color.name.toLowerCase()}, LED {from} (the start) in {color.startName}; the rest of the lights go dark.
                    {lightUp && !lighting ? ' They light up while this window is in front.' : ''}
                  </PropNote>
                )}
              </>
            ) : (
              <PropNote>No devices yet: light the object any bright color in the WLED app, its first LED in another.</PropNote>
            )}
          </PropSection>

          <PropSection id="photo-shot" title="2 · Scan or take a photo">
            <div className="flex flex-wrap gap-1.5">
              {canScan && !camera ? (
                <Button size="sm" variant="primary" onClick={() => void openCamera()}>
                  <ScanLine /> Scan with the camera
                </Button>
              ) : null}
              <Button size="sm" variant={photo || canScan ? 'secondary' : 'primary'} loading={loading} onClick={() => cameraInput.current?.click()}>
                <Camera /> {photo ? 'Another photo' : 'Take a photo'}
              </Button>
              <Button size="sm" onClick={() => fileInput.current?.click()} disabled={loading}>
                <ImagePlus /> Choose a picture
              </Button>
            </div>
            {problem ? <PropNote tone="red">{problem}</PropNote> : null}
            {devices.length && typeof window !== 'undefined' && !window.isSecureContext ? <PropNote>Open the admin console at its https:// address to scan with the camera.</PropNote> : null}
            {canScan ? <PropNote>A scan makes the LEDs blink their numbers in color and reads them with the camera: the exact order, even where the wire crosses itself.</PropNote> : null}
            {photo?.scanned != null ? (
              <PropNote>
                {photo.scanned} of {photo.lit} LEDs read by their numbers{dots.length > photo.scanned ? `; ${dots.length - photo.scanned} more seen but not read (red)` : ''}. Tap Automatic order to guess from the shape instead.
              </PropNote>
            ) : photo ? (
              <>
                <PropRow label="Sensitivity" hint="More finds fainter LEDs; less leaves out stray light">
                  <input
                    type="range"
                    min={0}
                    max={THRESHOLDS.length - 1}
                    value={THRESHOLDS.length - 1 - (level ?? 0)}
                    onChange={(e) => detect(photo, THRESHOLDS[THRESHOLDS.length - 1 - Number(e.target.value)])}
                    className="w-full accent-sky-600"
                    aria-label="Sensitivity"
                  />
                </PropRow>
                <PropNote>
                  {dots.length} light{dots.length === 1 ? '' : 's'} found{photo.lit ? ` of ${photo.lit} lit` : ''}
                  {loose && wire.length ? `, ${loose} not on the wire (red)` : ''}.{' '}
                  {startId != null ? 'The first LED was found.' : dots.length ? 'The first LED was not found: pick it with First LED.' : 'Try more sensitivity, another color, or trace the wire by hand.'}
                </PropNote>
              </>
            ) : null}
          </PropSection>

          <PropSection id="photo-size" title="3 · Size">
            <PropNumber
              label="Width"
              decimal
              step={0.1}
              min={0.01}
              max={300}
              unit={units}
              value={shownWidth > 0 ? Math.round((shownWidth / perUnit) * 100) / 100 : null}
              placeholder="—"
              onChange={(n) => setWidthM(n * perUnit)}
            />
            <PropNote>
              {widthM
                ? 'As you typed it.'
                : fromSpacing
                  ? 'From the light string’s LED spacing. Type the real width to change it.'
                  : 'Type the real width: pick the light string in the designer and the LED spacing sizes it.'}
            </PropNote>
          </PropSection>
        </div>
      </div>
    </Dialog>
  );
}
