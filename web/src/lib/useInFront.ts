import { useEffect, useState } from 'react';

/**
 * True while this window is visible and has focus. An editor that shows its work on the real
 * lights does so only then: one left open behind other windows or in a background tab must not
 * take the lights from a scene, a game or the public page's colors. (A background tab's timers
 * still run about once a minute, and a window behind others can still count as "visible".)
 */
export function useInFront(): boolean {
  const read = () => document.visibilityState === 'visible' && document.hasFocus();
  const [inFront, setInFront] = useState(read);
  useEffect(() => {
    const on = () => setInFront(read());
    document.addEventListener('visibilitychange', on);
    window.addEventListener('focus', on);
    window.addEventListener('blur', on);
    return () => {
      document.removeEventListener('visibilitychange', on);
      window.removeEventListener('focus', on);
      window.removeEventListener('blur', on);
    };
  }, []);
  return inFront;
}
