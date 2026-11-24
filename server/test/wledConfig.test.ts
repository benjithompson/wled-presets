import { describe, expect, it } from 'vitest';
import {
  configPatch,
  DEFAULT_LED_TYPES,
  gammaOf,
  limiterOf,
  newOutput,
  outputProblems,
  parseSettingsScript,
  protectedSection,
  setGamma,
  setLimiter,
  setOutputLength,
  setOutputType,
  setPath,
  unappliedPaths,
  type WledOutput
} from '../../shared/wledConfig.ts';

const out = (start: number, len: number, pin: number, extra: Partial<WledOutput> = {}): WledOutput => ({ start, len, pin: [pin], order: 1, rev: false, skip: 0, type: 22, ledma: 30, maxpwr: 0, ...extra });

describe('the settings sent to a device', () => {
  it('sends only what changed, arrays whole', () => {
    const before = { id: { name: 'WLED', mdns: 'wled-1' }, hw: { led: { fps: 42, ins: [out(0, 600, 16), out(600, 600, 3)] } }, nw: { ins: [{ ssid: 'home' }] } };
    expect(configPatch(before, structuredClone(before))).toBeUndefined();
    const after = setPath(setPath(before, 'id.name', 'Roof'), 'hw.led.ins', [out(0, 600, 16), out(600, 350, 3)]);
    expect(configPatch(before, after)).toEqual({ id: { name: 'Roof' }, hw: { led: { ins: [out(0, 600, 16), out(600, 350, 3)] } } });
    // The copy is new on the way down; the original is untouched.
    expect(before.id.name).toBe('WLED');
    expect(after.nw).toBe(before.nw);
  });

  it('refuses Wi-Fi, the access point and the update lock', () => {
    expect(protectedSection({ nw: { ins: [] } })).toBe('Wi-Fi');
    expect(protectedSection({ ota: { lock: true } })).toBe('security and updates');
    expect(protectedSection({ hw: {}, id: {} })).toBeNull();
  });

  it('finds what the device did not take', () => {
    const patch = { light: { gc: { col: 2.2 } }, hw: { led: { ins: [out(0, 600, 16), out(600, 600, 3)] } } };
    expect(unappliedPaths(patch, { light: { gc: { col: 2.2000000476837 } }, hw: { led: { ins: [out(0, 600, 16), out(600, 600, 3)] } } })).toEqual([]);
    expect(unappliedPaths(patch, { light: { gc: { col: 2.2 } }, hw: { led: { ins: [out(0, 600, 16)] } } })).toEqual(['hw.led.ins']);
    expect(unappliedPaths(patch, { light: { gc: { col: 2.2 } }, hw: { led: { ins: [out(0, 600, 16), out(600, 600, 4)] } } })).toEqual(['hw.led.ins.1.pin.0']);
  });
});

describe('LED outputs', () => {
  it('moves the outputs that follow on when one gets longer or shorter', () => {
    const outputs = [out(0, 600, 16), out(600, 600, 3), out(1200, 50, 4), out(2000, 10, 5)];
    expect(setOutputLength(outputs, 0, 500).map((o) => o.start)).toEqual([0, 500, 1100, 2000]);
    expect(setOutputLength(outputs, 1, 700).map((o) => [o.start, o.len])).toEqual([
      [0, 600],
      [600, 700],
      [1300, 50],
      [2000, 10]
    ]);
  });

  it('gives a type as many pins as it takes', () => {
    const apa102 = DEFAULT_LED_TYPES.find((t) => t.id === 51)!;
    const pwmRgb = DEFAULT_LED_TYPES.find((t) => t.id === 43)!;
    expect(setOutputType(out(0, 10, 16), apa102).pin).toEqual([16, -1]);
    expect(setOutputType(out(0, 10, 16), pwmRgb).pin).toEqual([16, -1, -1]);
    expect(setOutputType(out(0, 10, 16, { pin: [16, 17] }), DEFAULT_LED_TYPES[0]).pin).toEqual([16]);
  });

  it('adds an output after the last, with no pin yet, and says what is wrong', () => {
    const outputs = [out(0, 600, 16)];
    const added = newOutput(outputs, DEFAULT_LED_TYPES);
    expect(added).toMatchObject({ start: 600, len: 600, type: 22, pin: [-1] });
    const gpio = { reserved: [6, 7], readOnly: [34], max: 39 };
    expect(outputProblems([...outputs, added], DEFAULT_LED_TYPES, gpio)).toEqual(['Output 2 needs a GPIO pin.']);
    expect(outputProblems([out(0, 10, 16), out(10, 10, 16), out(20, 10, 34), out(30, 0, 6)], DEFAULT_LED_TYPES, gpio)).toEqual([
      'Output 2 uses GPIO 16, as output 1 does.',
      'Output 3: GPIO 34 is input only.',
      'Output 4 needs at least one LED.',
      'Output 4: GPIO 6 is taken on this board.'
    ]);
  });
});

describe('the brightness limiter', () => {
  const cfg = { hw: { led: { maxpwr: 0, ins: [out(0, 600, 16, { maxpwr: 8500 }), out(600, 200, 3, { maxpwr: 2000 })] } } };

  it('reads per-output limits when the device has none of its own', () => {
    expect(limiterOf(cfg)).toEqual({ mode: 'output', ma: 10500 });
    expect(limiterOf(setLimiter(cfg, 'off'))).toEqual({ mode: 'off', ma: 0 });
  });

  it('shares a device limit between the outputs by LEDs', () => {
    const one = setLimiter(cfg, 'device', 8000);
    expect(limiterOf(one)).toEqual({ mode: 'device', ma: 8000 });
    expect(one.hw.led.ins.map((o: WledOutput) => o.maxpwr)).toEqual([6000, 2000]);
    // Back to each output: they keep a share of the device's.
    expect(setLimiter(setLimiter(one, 'off'), 'output').hw.led.ins.map((o: WledOutput) => o.maxpwr)).toEqual([3750, 1250]);
  });
});

describe('gamma', () => {
  it('reads and writes the one value for colors and brightness', () => {
    const cfg = { light: { gc: { bri: 1, col: 2.2, val: 2.2 } } };
    expect(gammaOf(cfg)).toEqual({ colors: true, brightness: false, value: 2.2 });
    expect(setGamma(cfg, { colors: true, brightness: true, value: 2.8 }).light.gc).toEqual({ bri: 2.8, col: 2.8, val: 2.8 });
    expect(setGamma(cfg, { colors: false, brightness: false, value: 2.2 }).light.gc).toEqual({ bri: 1, col: 1, val: 2.2 });
  });
});

describe("a device's LED settings script", () => {
  it('reads the LED types and GPIO pins', () => {
    const js =
      'function GetV(){var d=document;d.um_p=[-1,32];d.rsvd=[6,7,8];d.ro_gpio=[34,35];d.max_gpio=40;d.touch=[0,2];' +
      'd.ledTypes=[{i:22,c:1,t:"D",n:"WS281x RGB"},{i:30,c:3,t:"D",n:"SK6812/WS2814 RGBW"},{i:51,c:1,t:"2P",n:"APA102 RGB"},{i:44,c:3,t:"AAAA",n:"PWM RGBW"},{i:80,c:1,t:"N",n:"DDP RGB (network)"},{i:40,c:0,t:"",n:"On/Off"}];bLimits(4,2048);}';
    const { ledTypes, gpio } = parseSettingsScript(js);
    expect(gpio).toEqual({ reserved: [6, 7, 8, 32], readOnly: [34, 35], max: 40 });
    expect(ledTypes?.map((t) => [t.id, t.kind, t.pins, t.white])).toEqual([
      [22, 'digital', 1, false],
      [30, 'digital', 1, true],
      [51, 'spi', 2, false],
      [44, 'pwm', 4, true],
      [80, 'network', 4, false],
      [40, 'onoff', 1, false]
    ]);
  });

  it('has nothing to say for an old WLED', () => {
    expect(parseSettingsScript('function GetV(){var d=document;d.Sf.LC.value=30;}')).toEqual({ ledTypes: null, gpio: null });
  });
});
