// GLSL ES 3.00 shaders for the light field: a stable-fluids solver on the GPU
// (advection, vorticity confinement, Jacobi pressure projection), dye display, and
// spark particles that ride the velocity field.

const HEAD = `#version 300 es
precision highp float;
precision highp sampler2D;
`;

/** Full-screen triangle from gl_VertexID. No vertex buffers. */
export const fullscreenVS = `${HEAD}
out vec2 vUv;
void main() {
  vec2 p = vec2(float((gl_VertexID << 1) & 2), float(gl_VertexID & 2));
  vUv = p;
  gl_Position = vec4(p * 2.0 - 1.0, 0.0, 1.0);
}`;

const FS = `${HEAD}
in vec2 vUv;
out vec4 outColor;
`;

/** Neighbour coordinates for finite differences. */
const NEIGHBOURS = `
uniform vec2 uTexel;
vec2 L() { return vUv - vec2(uTexel.x, 0.0); }
vec2 R() { return vUv + vec2(uTexel.x, 0.0); }
vec2 T() { return vUv + vec2(0.0, uTexel.y); }
vec2 B() { return vUv - vec2(0.0, uTexel.y); }
`;

export const splatFS = `${FS}
uniform sampler2D uTarget;
uniform float uAspect;
uniform vec2 uPoint;
uniform vec3 uColor;
uniform float uRadius;
void main() {
  vec2 p = vUv - uPoint;
  p.x *= uAspect;
  vec3 s = exp(-dot(p, p) / uRadius) * uColor;
  outColor = vec4(texture(uTarget, vUv).xyz + s, 1.0);
}`;

export const advectFS = `${FS}
uniform sampler2D uVelocity;
uniform sampler2D uSource;
uniform vec2 uVelTexel;
uniform float uDt;
uniform float uDissipation;
void main() {
  vec2 coord = vUv - uDt * texture(uVelocity, vUv).xy * uVelTexel;
  outColor = vec4(texture(uSource, coord).xyz / (1.0 + uDissipation * uDt), 1.0);
}`;

export const divergenceFS = `${FS}${NEIGHBOURS}
uniform sampler2D uVelocity;
void main() {
  vec2 c = texture(uVelocity, vUv).xy;
  float l = texture(uVelocity, L()).x;
  float r = texture(uVelocity, R()).x;
  float t = texture(uVelocity, T()).y;
  float b = texture(uVelocity, B()).y;
  // Solid walls: reflect the normal velocity at the edges.
  if (L().x < 0.0) l = -c.x;
  if (R().x > 1.0) r = -c.x;
  if (T().y > 1.0) t = -c.y;
  if (B().y < 0.0) b = -c.y;
  outColor = vec4(0.5 * (r - l + t - b), 0.0, 0.0, 1.0);
}`;

export const curlFS = `${FS}${NEIGHBOURS}
uniform sampler2D uVelocity;
void main() {
  float l = texture(uVelocity, L()).y;
  float r = texture(uVelocity, R()).y;
  float t = texture(uVelocity, T()).x;
  float b = texture(uVelocity, B()).x;
  outColor = vec4(0.5 * (r - l - t + b), 0.0, 0.0, 1.0);
}`;

/** Vorticity confinement: puts back the small swirls that numerical diffusion removes. */
export const vorticityFS = `${FS}${NEIGHBOURS}
uniform sampler2D uVelocity;
uniform sampler2D uCurl;
uniform float uStrength;
uniform float uDt;
void main() {
  float l = texture(uCurl, L()).x;
  float r = texture(uCurl, R()).x;
  float t = texture(uCurl, T()).x;
  float b = texture(uCurl, B()).x;
  float c = texture(uCurl, vUv).x;
  vec2 f = 0.5 * vec2(abs(t) - abs(b), abs(r) - abs(l));
  f /= length(f) + 1e-4;
  f *= uStrength * c;
  f.y = -f.y;
  vec2 v = texture(uVelocity, vUv).xy + f * uDt;
  outColor = vec4(clamp(v, -1000.0, 1000.0), 0.0, 1.0);
}`;

export const pressureFS = `${FS}${NEIGHBOURS}
uniform sampler2D uPressure;
uniform sampler2D uDivergence;
void main() {
  float l = texture(uPressure, L()).x;
  float r = texture(uPressure, R()).x;
  float t = texture(uPressure, T()).x;
  float b = texture(uPressure, B()).x;
  float div = texture(uDivergence, vUv).x;
  outColor = vec4((l + r + t + b - div) * 0.25, 0.0, 0.0, 1.0);
}`;

export const gradientSubtractFS = `${FS}${NEIGHBOURS}
uniform sampler2D uPressure;
uniform sampler2D uVelocity;
void main() {
  float l = texture(uPressure, L()).x;
  float r = texture(uPressure, R()).x;
  float t = texture(uPressure, T()).x;
  float b = texture(uPressure, B()).x;
  vec2 v = texture(uVelocity, vUv).xy - 0.5 * vec2(r - l, t - b);
  outColor = vec4(v, 0.0, 1.0);
}`;

export const scaleFS = `${FS}
uniform sampler2D uTexture;
uniform float uValue;
void main() { outColor = uValue * texture(uTexture, vUv); }`;

/** Tone-mapped dye with a soft glow, vignette and dithering. Two looks: light and dark. */
export const displayFS = `${FS}
uniform sampler2D uDye;
uniform vec2 uDyeTexel;
uniform vec3 uBackground;
uniform float uDark;
uniform float uTime;
uniform float uAspect;

float hash(vec2 p) { return fract(sin(dot(p, vec2(12.9898, 78.233))) * 43758.5453); }

void main() {
  vec3 c = texture(uDye, vUv).rgb;
  // Cheap glow: a ring of wide taps around the pixel.
  vec3 glow = vec3(0.0);
  for (int i = 0; i < 8; i++) {
    float a = float(i) * 0.7853982;
    vec2 d = vec2(cos(a), sin(a)) * uDyeTexel * 14.0;
    glow += texture(uDye, vUv + d).rgb + texture(uDye, vUv + d * 2.2).rgb * 0.6;
  }
  glow /= 12.8;
  vec3 hdr = c * 1.4 + glow * 0.45;
  // Keep mixed colors vivid: push away from grey before tone mapping.
  float l = dot(hdr, vec3(0.2126, 0.7152, 0.0722));
  hdr = max(mix(vec3(l), hdr, 1.35), 0.0);
  vec3 col = 1.0 - exp(-hdr);

  vec2 q = vUv - 0.5;
  q.x *= uAspect;
  float vignette = smoothstep(1.25, 0.25, length(q));

  vec3 outRgb;
  if (uDark > 0.5) {
    outRgb = uBackground + col * mix(0.55, 1.0, vignette);
  } else {
    // Light theme: watercolour. The dye stains the paper instead of glowing on it.
    float m = max(hdr.r, max(hdr.g, hdr.b));
    vec3 tint = hdr / max(m, 1e-3);
    tint = mix(tint, vec3(dot(tint, vec3(0.299, 0.587, 0.114))), 0.1) * 0.88;
    float ink = (1.0 - exp(-m * 2.6)) * 0.85 * mix(0.75, 1.0, vignette);
    outRgb = mix(uBackground, tint, ink);
  }
  outRgb += (hash(gl_FragCoord.xy + fract(uTime)) - 0.5) / 255.0;
  outColor = vec4(outRgb, 1.0);
}`;

/** Moves sparks with the fluid. State per texel: position (xy), life (z), seed (w). */
export const particleUpdateFS = `${FS}
uniform sampler2D uState;
uniform sampler2D uVelocity;
uniform vec2 uVelTexel;
uniform float uDt;
uniform float uTime;

float hash(float n) { return fract(sin(n) * 43758.5453123); }

void main() {
  vec4 s = texelFetch(uState, ivec2(gl_FragCoord.xy), 0);
  vec2 p = s.xy;
  float life = s.z;
  float seed = s.w;
  vec2 v = texture(uVelocity, p).xy * uVelTexel;
  vec2 jitter = vec2(hash(seed * 91.7 + uTime), hash(seed * 47.3 + uTime * 1.3)) - 0.5;
  // Brownian drift per unit of simulation time, so it slows with the rest.
  p += v * uDt + jitter * 0.06 * uDt;
  life -= uDt * (0.05 + 0.1 * fract(seed * 7.13));
  if (life <= 0.0 || p.x < 0.0 || p.x > 1.0 || p.y < 0.0 || p.y > 1.0) {
    p = vec2(hash(seed * 13.1 + uTime), hash(seed * 29.7 + uTime * 0.7));
    life = 1.0;
  }
  outColor = vec4(p, life, seed);
}`;

export const particleVS = `${HEAD}
uniform sampler2D uState;
uniform sampler2D uDye;
uniform int uWidth;
uniform float uPointSize;
uniform float uDark;
out vec3 vColor;
out float vAlpha;
void main() {
  ivec2 c = ivec2(gl_VertexID % uWidth, gl_VertexID / uWidth);
  vec4 s = texelFetch(uState, c, 0);
  vec3 dye = texture(uDye, s.xy).rgb;
  float lum = max(dye.r, max(dye.g, dye.b));
  float fade = smoothstep(0.0, 0.2, s.z) * smoothstep(1.0, 0.85, s.z);
  float twinkle = 0.65 + 0.35 * sin(s.z * 40.0 + s.w * 100.0);
  vec3 tint = 1.0 - exp(-dye * 3.0);
  if (uDark > 0.5) {
    vColor = tint * 1.2 + 0.3;
    vAlpha = fade * twinkle * clamp(lum * 3.0, 0.1, 1.0);
  } else {
    vColor = tint / max(max(tint.r, max(tint.g, tint.b)), 1e-3) * 0.75;
    vAlpha = fade * twinkle * clamp(lum * 2.0, 0.0, 0.7);
  }
  gl_Position = vec4(s.xy * 2.0 - 1.0, 0.0, 1.0);
  gl_PointSize = uPointSize * (0.5 + fract(s.w * 13.7) * 1.5);
}`;

export const particleFS = `${HEAD}
in vec3 vColor;
in float vAlpha;
out vec4 outColor;
void main() {
  vec2 d = gl_PointCoord - 0.5;
  float a = exp(-dot(d, d) * 14.0) * vAlpha;
  outColor = vec4(vColor * a, a);
}`;
