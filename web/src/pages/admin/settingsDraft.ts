import { useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { toast } from 'sonner';
import type { Settings } from '../../../../shared/types.ts';
import { api, type Overview } from '../../lib/api.ts';
import { errorText } from '../../lib/utils.ts';
import { OVERVIEW, useOverview } from './AdminLayout.tsx';

/**
 * Some of the site's settings, to change and save on their own: each card (on the page the
 * settings belong to) keeps a draft of its keys and saves them over the rest as they are.
 * `prepare` tidies the draft before it is sent (numbers kept in range).
 */
export function useSettingsDraft<K extends keyof Settings>(keys: readonly K[], prepare: (v: Pick<Settings, K>) => Pick<Settings, K> = (v) => v) {
  const qc = useQueryClient();
  const { data } = useOverview();
  const [draft, setDraft] = useState<Pick<Settings, K> | null>(null);
  const pick = (s: Settings) => Object.fromEntries(keys.map((k) => [k, s[k]])) as Pick<Settings, K>;
  const saved = data ? pick(data.settings) : null;
  const value = draft ?? saved;
  const dirty = !!draft && !!saved && JSON.stringify(draft) !== JSON.stringify(saved);

  const mutation = useMutation({
    mutationFn: (v: Pick<Settings, K>) => {
      // The newest of the other settings: another card may have saved since this page loaded.
      const all = qc.getQueryData<Overview>(OVERVIEW)?.settings ?? data!.settings;
      return api.saveSettings({ ...all, ...prepare(v) });
    },
    onSuccess: (s) => {
      qc.setQueryData<Overview>(OVERVIEW, (o) => (o ? { ...o, settings: s } : o));
      void qc.invalidateQueries({ queryKey: OVERVIEW });
      setDraft(null);
      toast.success('Saved');
    },
    onError: (e) => toast.error(errorText(e))
  });

  return {
    data,
    value,
    dirty,
    saving: mutation.isPending,
    set: <F extends K>(k: F, v: Settings[F]) => value && setDraft({ ...value, [k]: v }),
    save: () => value && mutation.mutate(value),
    undo: () => setDraft(null)
  };
}
