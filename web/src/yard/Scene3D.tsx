import { useEffect, useRef, useState } from 'react';
import * as THREE from 'three';
import { OrbitControls } from 'three/addons/controls/OrbitControls.js';
import { buildStage, FEET_PER_METER, isLine, layoutGround, layoutScale, type Layout, type Stage } from '../../../shared/layout.ts';
import { cn } from '../lib/utils.ts';

type CameraPreset = 'street' | 'front' | 'top' | 'side';

const PRESETS: { id: CameraPreset; label: string }[] = [
  { id: 'street', label: 'Street' },
  { id: 'front', label: 'Front' },
  { id: 'top', label: 'Top' },
  { id: 'side', label: 'Side' }
];

/** A soft round dot, for the LEDs and their glow. */
function dotTexture() {
  const c = document.createElement('canvas');
  c.width = c.height = 64;
  const g = c.getContext('2d')!;
  const grad = g.createRadialGradient(32, 32, 0, 32, 32, 32);
  grad.addColorStop(0, 'rgba(255,255,255,1)');
  grad.addColorStop(0.35, 'rgba(255,255,255,0.8)');
  grad.addColorStop(1, 'rgba(255,255,255,0)');
  g.fillStyle = grad;
  g.fillRect(0, 0, 64, 64);
  const t = new THREE.CanvasTexture(c);
  t.colorSpace = THREE.SRGBColorSpace;
  return t;
}

interface Ctx {
  renderer: THREE.WebGLRenderer;
  scene: THREE.Scene;
  camera: THREE.PerspectiveCamera;
  controls: OrbitControls;
  content: THREE.Group;
  bulbs: THREE.Points | null;
  glow: THREE.Points | null;
  stage: Stage | null;
  /** Camera move in progress (to a preset). */
  fly: { from: THREE.Vector3; to: THREE.Vector3; fromT: THREE.Vector3; toT: THREE.Vector3; start: number } | null;
  bounds: { center: THREE.Vector3; size: number };
  fitted: boolean;
}

/**
 * The yard in 3D, in meters: the house front is at depth 0, the ground at height 0. Every LED
 * glows in the color of the current frame (`getFrame`, as in YardView). Drag to turn, scroll
 * to zoom, right-drag (or two fingers) to pan. A click on an LED selects its object.
 */
export function Scene3D({
  layout,
  getFrame,
  selected,
  onSelect,
  className,
  fill = false
}: {
  layout: Layout;
  getFrame: (t: number) => Uint8Array | null;
  selected: string | null;
  onSelect: (id: string | null) => void;
  className?: string;
  /** Fill the parent (which must be positioned) instead of a 16:9 box. */
  fill?: boolean;
}) {
  const host = useRef<HTMLDivElement>(null);
  const ctx = useRef<Ctx | null>(null);
  const getFrameRef = useRef(getFrame);
  getFrameRef.current = getFrame;
  const onSelectRef = useRef(onSelect);
  onSelectRef.current = onSelect;
  const [showPicture, setShowPicture] = useState(true);
  const [failed, setFailed] = useState(false);

  // The renderer, camera, controls and the drawing loop: once.
  useEffect(() => {
    const el = host.current;
    if (!el) return;
    let renderer: THREE.WebGLRenderer;
    try {
      renderer = new THREE.WebGLRenderer({ antialias: true });
    } catch {
      setFailed(true);
      return;
    }
    renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
    renderer.setClearColor(0x05070f);
    el.appendChild(renderer.domElement);
    renderer.domElement.className = 'absolute inset-0 h-full w-full';
    const scene = new THREE.Scene();
    scene.fog = new THREE.Fog(0x05070f, 40, 120);
    const camera = new THREE.PerspectiveCamera(45, 1, 0.05, 500);
    camera.position.set(0, 4, 22);
    const controls = new OrbitControls(camera, renderer.domElement);
    controls.enableDamping = true;
    controls.dampingFactor = 0.12;
    controls.maxPolarAngle = Math.PI * 0.495;
    controls.target.set(0, 3, 0);
    const content = new THREE.Group();
    scene.add(content);
    const c: Ctx = { renderer, scene, camera, controls, content, bulbs: null, glow: null, stage: null, fly: null, bounds: { center: new THREE.Vector3(0, 3, 0), size: 20 }, fitted: false };
    ctx.current = c;

    const resize = () => {
      const w = el.clientWidth;
      const h = el.clientHeight;
      if (!w || !h) return;
      renderer.setSize(w, h, false);
      camera.aspect = w / h;
      camera.updateProjectionMatrix();
    };
    const ro = new ResizeObserver(resize);
    ro.observe(el);
    resize();

    // A click (not a drag) on an LED selects its object; on empty space it clears the selection.
    const ray = new THREE.Raycaster();
    let down: { x: number; y: number } | null = null;
    const onDown = (e: PointerEvent) => (down = { x: e.clientX, y: e.clientY });
    const onUp = (e: PointerEvent) => {
      if (!down || Math.hypot(e.clientX - down.x, e.clientY - down.y) > 5 || !c.bulbs || !c.stage) return;
      down = null;
      const r = renderer.domElement.getBoundingClientRect();
      const ndc = new THREE.Vector2(((e.clientX - r.left) / r.width) * 2 - 1, -((e.clientY - r.top) / r.height) * 2 + 1);
      ray.setFromCamera(ndc, camera);
      ray.params.Points = { threshold: Math.max(0.08, camera.position.distanceTo(controls.target) * 0.012) };
      const hit = ray.intersectObject(c.bulbs).sort((a, b) => (a.distanceToRay ?? 0) - (b.distanceToRay ?? 0))[0];
      const i = hit?.index;
      const f = i == null ? undefined : c.stage.fixtures.find((s) => i >= s.offset && i < s.offset + s.count);
      onSelectRef.current(f?.id ?? null);
    };
    renderer.domElement.addEventListener('pointerdown', onDown);
    renderer.domElement.addEventListener('pointerup', onUp);

    let raf = 0;
    const t0 = performance.now();
    const loop = () => {
      raf = requestAnimationFrame(loop);
      if (c.fly) {
        const k = Math.min(1, (performance.now() - c.fly.start) / 600);
        const e = 1 - (1 - k) ** 3;
        camera.position.lerpVectors(c.fly.from, c.fly.to, e);
        controls.target.lerpVectors(c.fly.fromT, c.fly.toT, e);
        if (k >= 1) c.fly = null;
      }
      controls.update();
      paintLeds(c, getFrameRef.current((performance.now() - t0) / 1000));
      renderer.render(scene, camera);
    };
    raf = requestAnimationFrame(loop);

    return () => {
      cancelAnimationFrame(raf);
      ro.disconnect();
      renderer.domElement.removeEventListener('pointerdown', onDown);
      renderer.domElement.removeEventListener('pointerup', onUp);
      controls.dispose();
      disposeGroup(content);
      scene.traverse((o) => disposeObject(o));
      renderer.dispose();
      renderer.domElement.remove();
      ctx.current = null;
    };
  }, []);

  // The objects: rebuilt when the layout or the selection changes. The camera stays where it is.
  useEffect(() => {
    const c = ctx.current;
    if (!c) return;
    disposeGroup(c.content);
    c.content.clear();
    const stage = buildStage(layout);
    c.stage = stage;
    const scale = layoutScale(layout);
    const ground = layoutGround(layout);
    const world = (x: number, y: number, z: number) => new THREE.Vector3((x - layout.width / 2) / scale, (ground - y) / scale, z / scale);

    // Ground grid (1 m, or 5 ft) and the front wall of the house.
    const step = layout.units === 'm' ? 1 : 5 / FEET_PER_METER;
    const extent = Math.max(30, (layout.width / scale) * 1.6);
    const divisions = Math.round(extent / step);
    const grid = new THREE.GridHelper(divisions * step, divisions, 0x1c2230, 0x121722);
    c.content.add(grid);
    const wall = new THREE.Line(
      new THREE.BufferGeometry().setFromPoints([world(0, ground, 0), world(layout.width, ground, 0)]),
      new THREE.LineBasicMaterial({ color: 0xfbbf24, transparent: true, opacity: 0.4 })
    );
    c.content.add(wall);

    // The house picture, on the front wall.
    if (layout.background && showPicture) {
      const tex = new THREE.TextureLoader().load(layout.background);
      tex.colorSpace = THREE.SRGBColorSpace;
      const plane = new THREE.Mesh(
        new THREE.PlaneGeometry(layout.width / scale, layout.height / scale),
        new THREE.MeshBasicMaterial({ map: tex, transparent: true, opacity: 0.45, depthWrite: false, side: THREE.DoubleSide })
      );
      plane.position.copy(world(layout.width / 2, layout.height / 2, -2));
      c.content.add(plane);
    }

    // Wires of the lines, so their shape shows even where the LEDs are off.
    layout.fixtures.forEach((f) => {
      if (!isLine(f) || f.points.length < 2) return;
      const hl = f.id === selected;
      const line = new THREE.Line(
        new THREE.BufferGeometry().setFromPoints(f.points.map((p) => world(p.x, p.y, p.z ?? 0))),
        new THREE.LineBasicMaterial({ color: hl ? 0x28aaff : 0xffffff, transparent: true, opacity: hl ? 0.9 : 0.12 })
      );
      c.content.add(line);
    });

    // LEDs: a small bright bulb and a wide soft glow, both in the frame's colors.
    const n = stage.pixelCount;
    const pos = new Float32Array(n * 3);
    const box = new THREE.Box3();
    for (let i = 0; i < n; i++) {
      const v = world(stage.positions3[i * 3], stage.positions3[i * 3 + 1], stage.positions3[i * 3 + 2]);
      pos.set([v.x, v.y, v.z], i * 3);
      box.expandByPoint(v);
    }
    const tex = dotTexture();
    const make = (size: number, opacity: number) => {
      const g = new THREE.BufferGeometry();
      g.setAttribute('position', new THREE.BufferAttribute(pos, 3));
      g.setAttribute('color', new THREE.BufferAttribute(new Float32Array(n * 3), 3));
      const m = new THREE.PointsMaterial({ size, map: tex, vertexColors: true, transparent: true, opacity, depthWrite: false, blending: THREE.AdditiveBlending, sizeAttenuation: true });
      const p = new THREE.Points(g, m);
      c.content.add(p);
      return p;
    };
    c.glow = make(0.55, 0.35);
    c.bulbs = make(0.11, 1);

    if (n) {
      c.bounds = { center: box.getCenter(new THREE.Vector3()), size: Math.max(4, box.getSize(new THREE.Vector3()).length()) };
      if (!c.fitted) {
        c.fitted = true;
        flyTo(c, 'street', true);
      }
    }
  }, [layout, selected, showPicture]);

  if (failed) {
    return (
      <div className={cn('grid place-items-center bg-[#05070f] p-6 text-center text-sm text-white/60', fill ? 'absolute inset-0' : 'aspect-video rounded-2xl ring-1 ring-white/10', className)}>
        This browser cannot show the 3D view (WebGL is off or not supported).
      </div>
    );
  }

  return (
    <div className={cn('overflow-hidden bg-[#05070f]', fill ? 'absolute inset-0' : 'relative aspect-video max-h-[70dvh] w-full rounded-2xl ring-1 ring-white/10', className)}>
      <div ref={host} className="absolute inset-0 touch-none" />
      <div className="absolute top-2 right-2 flex flex-wrap justify-end gap-1">
        {PRESETS.map((p) => (
          <button
            key={p.id}
            type="button"
            onClick={() => ctx.current && flyTo(ctx.current, p.id)}
            className="rounded-lg bg-black/50 px-2.5 py-1 text-xs font-medium text-white/80 ring-1 ring-white/10 backdrop-blur hover:bg-black/70 hover:text-white"
          >
            {p.label}
          </button>
        ))}
        {layout.background ? (
          <button
            type="button"
            aria-pressed={showPicture}
            onClick={() => setShowPicture((v) => !v)}
            className={cn('rounded-lg px-2.5 py-1 text-xs font-medium ring-1 ring-white/10 backdrop-blur', showPicture ? 'bg-white/80 text-stone-900' : 'bg-black/50 text-white/80 hover:bg-black/70')}
          >
            Picture
          </button>
        ) : null}
      </div>
      <p className="pointer-events-none absolute bottom-2 left-3 text-xs text-white/45">Drag to turn · scroll to zoom · right-drag to pan · click an LED to select its object</p>
    </div>
  );
}

/** Copies the frame's colors to the LEDs. Unlit LEDs show as faint dots; skipped LEDs not at all. */
function paintLeds(c: Ctx, frame: Uint8Array | null) {
  if (!c.bulbs || !c.glow || !c.stage) return;
  const bulbs = c.bulbs.geometry.getAttribute('color') as THREE.BufferAttribute;
  const glow = c.glow.geometry.getAttribute('color') as THREE.BufferAttribute;
  const b = bulbs.array as Float32Array;
  const g = glow.array as Float32Array;
  const n = c.stage.pixelCount;
  const active = c.stage.active;
  for (let i = 0; i < n; i++) {
    const r = frame ? frame[i * 3] / 255 : 0;
    const gg = frame ? frame[i * 3 + 1] / 255 : 0;
    const bb = frame ? frame[i * 3 + 2] / 255 : 0;
    const lit = r + gg + bb > 0.03;
    const dim = active[i] && !lit ? 0.07 : 0;
    b[i * 3] = r + dim;
    b[i * 3 + 1] = gg + dim;
    b[i * 3 + 2] = bb + dim;
    g[i * 3] = r;
    g[i * 3 + 1] = gg;
    g[i * 3 + 2] = bb;
  }
  bulbs.needsUpdate = true;
  glow.needsUpdate = true;
}

function flyTo(c: Ctx, preset: CameraPreset, now = false) {
  const { center, size } = c.bounds;
  const d = size * 1.15;
  const offset =
    preset === 'street'
      ? new THREE.Vector3(size * 0.18, size * 0.22, d)
      : preset === 'front'
        ? new THREE.Vector3(0, 0, d)
        : preset === 'top'
          ? new THREE.Vector3(0, d, 0.01)
          : new THREE.Vector3(d, size * 0.1, 0);
  const to = center.clone().add(offset);
  if (now) {
    c.camera.position.copy(to);
    c.controls.target.copy(center);
    return;
  }
  c.fly = { from: c.camera.position.clone(), to, fromT: c.controls.target.clone(), toT: center.clone(), start: performance.now() };
}

function disposeObject(o: THREE.Object3D) {
  const m = o as THREE.Mesh;
  m.geometry?.dispose();
  const mats = Array.isArray(m.material) ? m.material : m.material ? [m.material] : [];
  for (const mat of mats) {
    (mat as THREE.MeshBasicMaterial).map?.dispose();
    mat.dispose();
  }
}

function disposeGroup(g: THREE.Group) {
  g.traverse((o) => o !== g && disposeObject(o));
}
