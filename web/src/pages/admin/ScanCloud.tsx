// The LEDs a 3D scan placed, to turn round and look at: each in a color along the wire (LED 0
// green and bigger), the wire through them, and where each scan's camera stood (or, walked round
// in AR, the way the phone went).
import { useEffect, useRef, useState } from 'react';
import * as THREE from 'three';
import { OrbitControls } from 'three/addons/controls/OrbitControls.js';
import { wire3d, type Pt3 } from '../../../../shared/scan3d.ts';

export function ScanCloud({ points, cameras, mirror }: { points: (Pt3 | null)[]; cameras: Pt3[]; mirror: boolean }) {
  const host = useRef<HTMLDivElement>(null);
  const ctx = useRef<{ scene: THREE.Scene; content: THREE.Group; camera: THREE.PerspectiveCamera; controls: OrbitControls } | null>(null);
  const [failed, setFailed] = useState(false);

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
    renderer.domElement.className = 'absolute inset-0 h-full w-full';
    el.appendChild(renderer.domElement);
    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(40, 1, 0.01, 100);
    const controls = new OrbitControls(camera, renderer.domElement);
    controls.enableDamping = true;
    controls.dampingFactor = 0.12;
    const content = new THREE.Group();
    scene.add(content);
    ctx.current = { scene, content, camera, controls };
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
    let raf = 0;
    const loop = () => {
      raf = requestAnimationFrame(loop);
      controls.update();
      renderer.render(scene, camera);
    };
    raf = requestAnimationFrame(loop);
    return () => {
      cancelAnimationFrame(raf);
      ro.disconnect();
      controls.dispose();
      clear(content);
      renderer.dispose();
      renderer.domElement.remove();
      ctx.current = null;
    };
  }, []);

  useEffect(() => {
    const c = ctx.current;
    if (!c) return;
    clear(c.content);
    const placed = points.filter((p): p is Pt3 => !!p);
    if (!placed.length) return;
    const lo = (k: 'x' | 'y' | 'z') => Math.min(...placed.map((p) => p[k]));
    const hi = (k: 'x' | 'y' | 'z') => Math.max(...placed.map((p) => p[k]));
    const mid = { x: (lo('x') + hi('x')) / 2, y: (lo('y') + hi('y')) / 2, z: (lo('z') + hi('z')) / 2 };
    const size = Math.max(hi('x') - lo('x'), hi('y') - lo('y'), hi('z') - lo('z')) || 1;
    // Sized to about 1 across, the middle at 0; mirrored: front and back swap.
    const at = (p: Pt3) => new THREE.Vector3((p.x - mid.x) / size, (p.y - mid.y) / size, ((mirror ? -1 : 1) * (p.z - mid.z)) / size);

    for (const run of wire3d(points)) {
      if (run.length < 2) continue;
      c.content.add(new THREE.Line(new THREE.BufferGeometry().setFromPoints(run.map(at)), new THREE.LineBasicMaterial({ color: 0x38bdf8, transparent: true, opacity: 0.45 })));
    }
    const pos: number[] = [];
    const col: number[] = [];
    const color = new THREE.Color();
    points.forEach((p, i) => {
      if (!p || i === 0) return;
      const v = at(p);
      pos.push(v.x, v.y, v.z);
      color.setHSL((i / points.length) * 0.8, 0.9, 0.6);
      col.push(color.r, color.g, color.b);
    });
    const g = new THREE.BufferGeometry();
    g.setAttribute('position', new THREE.Float32BufferAttribute(pos, 3));
    g.setAttribute('color', new THREE.Float32BufferAttribute(col, 3));
    c.content.add(new THREE.Points(g, new THREE.PointsMaterial({ size: 0.025, vertexColors: true, sizeAttenuation: true })));
    if (points[0]) {
      const first = new THREE.Mesh(new THREE.SphereGeometry(0.022, 12, 8), new THREE.MeshBasicMaterial({ color: 0x22c55e }));
      first.position.copy(at(points[0]));
      c.content.add(first);
    }
    const near = (cam: Pt3) => {
      const v = at(cam);
      const d = v.length();
      return d > 2.2 ? v.clone().multiplyScalar(2.2 / d) : v;
    };
    // A walk round (many pictures): the way the phone went, and where it started.
    if (cameras.length > 12) {
      c.content.add(new THREE.Line(new THREE.BufferGeometry().setFromPoints(cameras.map(near)), new THREE.LineBasicMaterial({ color: 0xfde68a, transparent: true, opacity: 0.5 })));
      const start = new THREE.Mesh(new THREE.SphereGeometry(0.03, 10, 6), new THREE.MeshBasicMaterial({ color: 0xfde68a }));
      start.position.copy(near(cameras[0]));
      c.content.add(start);
    }
    // Where the scans were taken from: a dot, and a faint line to the middle.
    for (const cam of cameras.length > 12 ? [] : cameras) {
      const v = near(cam);
      const m = new THREE.Mesh(new THREE.SphereGeometry(0.03, 10, 6), new THREE.MeshBasicMaterial({ color: 0xfde68a }));
      m.position.copy(v);
      c.content.add(m);
      const line = new THREE.Line(new THREE.BufferGeometry().setFromPoints([v, new THREE.Vector3()]), new THREE.LineDashedMaterial({ color: 0xfde68a, transparent: true, opacity: 0.3, dashSize: 0.05, gapSize: 0.05 }));
      line.computeLineDistances();
      c.content.add(line);
    }
    const grid = new THREE.GridHelper(2, 8, 0x1c2230, 0x121722);
    grid.position.y = (lo('y') - mid.y) / size - 0.02;
    c.content.add(grid);
  }, [points, cameras, mirror]);

  // From the front, a little above, once.
  useEffect(() => {
    const c = ctx.current;
    if (!c) return;
    c.camera.position.set(0.9, 0.7, 2.4);
    c.controls.target.set(0, 0, 0);
  }, []);

  return (
    <div ref={host} className="absolute inset-0">
      {failed ? <p className="absolute inset-0 grid place-items-center text-sm text-white/70">This browser cannot draw 3D.</p> : null}
    </div>
  );
}

function clear(g: THREE.Group) {
  for (const o of [...g.children]) {
    g.remove(o);
    const m = o as THREE.Mesh;
    m.geometry?.dispose();
    const mat = m.material as THREE.Material | THREE.Material[] | undefined;
    if (Array.isArray(mat)) mat.forEach((x) => x.dispose());
    else mat?.dispose();
  }
}
