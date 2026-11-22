import { describe, expect, it } from 'vitest';
import { emptySequence, type Sequence } from '../../shared/sequence.ts';
import { readSequenceFile, remapAudio, sequenceAudioIds, sequenceFileName, writeSequenceFile } from '../../shared/sequenceFile.ts';

const withMusic = (): Sequence => {
  const s = { ...emptySequence('Show / night: 1'), id: 'seq-1', updatedAt: '2026-01-01' };
  const clip = (id: string, fileId: string) => ({ id, fileId, name: 'Song', start: 0, offset: 0, duration: 10 });
  return { ...s, audio: [{ id: 'a1', name: 'Audio 1', volume: 1, clips: [clip('c1', 'f1'), clip('c2', 'f2'), clip('c3', 'f1')] }] };
};

describe('sequence files', () => {
  it('round-trips a sequence with its audio, without its id', () => {
    const seq = withMusic();
    const audio = [{ id: 'f1', name: 'Song.wav', type: 'audio/wav', data: 'UklGRg==' }];
    const back = readSequenceFile(writeSequenceFile(seq, audio));
    const { id: _id, updatedAt: _u, ...rest } = seq;
    expect(back).toEqual({ sequence: rest, audio });
  });

  it('opens a plain sequence as the API gives it', () => {
    const seq = withMusic();
    const back = readSequenceFile(JSON.stringify(seq));
    expect(back.audio).toEqual([]);
    expect(back.sequence).not.toHaveProperty('id');
    expect(back.sequence).toMatchObject({ name: seq.name, tracks: seq.tracks });
  });

  it('says what is wrong with a file that is not one', () => {
    expect(() => readSequenceFile('nope')).toThrow(/not JSON/);
    expect(() => readSequenceFile('[]')).toThrow(/not a sequence file/);
    expect(() => readSequenceFile('{"format":"other"}')).toThrow(/not a sequence file/);
    expect(() => readSequenceFile(JSON.stringify({ format: 'wled-presets-sequence', version: 99, sequence: {} }))).toThrow(/newer version/);
    expect(() => readSequenceFile(JSON.stringify({ format: 'wled-presets-sequence', version: 1 }))).toThrow(/no sequence/);
    const bad = { format: 'wled-presets-sequence', version: 1, sequence: {}, audio: [{ id: 'f1', name: 'x', type: 'text/html', data: '' }] };
    expect(() => readSequenceFile(JSON.stringify(bad))).toThrow(/damaged/);
  });

  it('lists the audio once each and points the clips at new files', () => {
    const seq = withMusic();
    expect(sequenceAudioIds(seq)).toEqual(['f1', 'f2']);
    const moved = remapAudio(seq, { f1: 'n1' });
    expect(moved.audio[0].clips.map((c) => c.fileId)).toEqual(['n1', 'f2', 'n1']);
  });

  it('names the file after the sequence', () => {
    expect(sequenceFileName('Show / night: 1')).toBe('Show night 1.wledseq');
    expect(sequenceFileName('  ')).toBe('Sequence.wledseq');
  });
});
