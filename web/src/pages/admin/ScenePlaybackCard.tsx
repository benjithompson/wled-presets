import { useMutation, useQueryClient } from '@tanstack/react-query';
import { SCENE_TRANSITION_SECONDS, TRANSITION_CHOICES, transitionInfo } from '../../../../shared/transitions.ts';
import type { Settings } from '../../../../shared/types.ts';
import { Button, Card, CardHeader, Field, Input, Select } from '../../components/ui.tsx';
import { api } from '../../lib/api.ts';
import { relativeTime } from '../../lib/utils.ts';
import { OVERVIEW } from './AdminLayout.tsx';
import { useSettingsDraft } from './settingsDraft.ts';

const KEYS = ['defaultSceneId', 'revertMinutes', 'sceneTransition', 'sceneTransitionSeconds'] as const;

/**
 * Admin → Scenes: how scenes play. The default scene the lights go back to after a visitor's
 * pick (the auto-revert), and the transition from one scene to the next.
 */
export function ScenePlaybackCard() {
  const qc = useQueryClient();
  const s = useSettingsDraft(KEYS, (v) => ({
    ...v,
    revertMinutes: Math.min(1440, Math.max(0, Math.round(v.revertMinutes) || 0)),
    sceneTransitionSeconds: Math.min(SCENE_TRANSITION_SECONDS.max, Math.max(SCENE_TRANSITION_SECONDS.min, v.sceneTransitionSeconds || SCENE_TRANSITION_SECONDS.default))
  }));
  const cancelRevert = useMutation({ mutationFn: api.cancelRevert, onSuccess: () => qc.invalidateQueries({ queryKey: OVERVIEW }) });
  if (!s.data || !s.value) return null;
  const v = s.value;
  const revertAt = s.data.state.revertAt;

  return (
    <Card>
      <CardHeader
        title="Playing scenes"
        description="Where the lights go back to after a visitor's pick, and how one scene gives way to the next."
        actions={
          s.dirty ? (
            <>
              <Button variant="ghost" onClick={s.undo}>
                Undo
              </Button>
              <Button variant="primary" onClick={s.save} loading={s.saving}>
                Save
              </Button>
            </>
          ) : null
        }
      />
      <div className="grid gap-5 p-5 sm:grid-cols-2">
        <Field label="Default scene" hint="After a visitor picks a scene or a color, the lights go back to it.">
          {(id) => (
            <Select id={id} value={v.defaultSceneId ?? ''} onChange={(e) => s.set('defaultSceneId', e.target.value || null)}>
              <option value="">None (no going back)</option>
              {s.data!.scenes.map((x) => (
                <option key={x.id} value={x.id}>
                  {x.name}
                </option>
              ))}
            </Select>
          )}
        </Field>
        <Field
          label="Back to it after (minutes)"
          hint={
            revertAt ? (
              <span>
                Next {relativeTime(revertAt)}.{' '}
                <button type="button" className="font-medium text-stone-700 underline-offset-2 hover:underline dark:text-stone-300" onClick={() => cancelRevert.mutate()}>
                  Cancel it
                </button>
              </span>
            ) : (
              '0: never.'
            )
          }
        >
          {(id) => <Input id={id} type="number" min={0} max={1440} step={1} value={v.revertMinutes} onChange={(e) => s.set('revertMinutes', Math.max(0, Number(e.target.value) || 0))} />}
        </Field>
        <Field
          label="Transition"
          hint={
            v.sceneTransition === 'none'
              ? 'The new scene shows at once.'
              : `${transitionInfo(v.sceneTransition).description} Effects and sequences transition; a device that plays a WLED preset changes as WLED does. Going back to the default scene changes at once.`
          }
        >
          {(id) => (
            <Select id={id} value={v.sceneTransition} onChange={(e) => s.set('sceneTransition', e.target.value as Settings['sceneTransition'])}>
              <option value="none">None (cut)</option>
              {TRANSITION_CHOICES.map((t) => (
                <option key={t.id} value={t.id}>
                  {t.name}
                </option>
              ))}
            </Select>
          )}
        </Field>
        <Field label="Transition length (seconds)" hint={`${SCENE_TRANSITION_SECONDS.min} to ${SCENE_TRANSITION_SECONDS.max} seconds.`}>
          {(id) => (
            <Input
              id={id}
              type="number"
              min={SCENE_TRANSITION_SECONDS.min}
              max={SCENE_TRANSITION_SECONDS.max}
              step={0.1}
              disabled={v.sceneTransition === 'none'}
              value={v.sceneTransitionSeconds}
              onChange={(e) => s.set('sceneTransitionSeconds', Math.max(0, Number(e.target.value) || 0))}
            />
          )}
        </Field>
      </div>
    </Card>
  );
}
