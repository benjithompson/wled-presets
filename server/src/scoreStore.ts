import type Database from 'better-sqlite3';
import type { HighScore, ScoreStore } from './game/kit.ts';

/** The games' scoreboards in the database: they stay through restarts and updates. */
export function databaseScores(db: Database.Database): ScoreStore {
  const stmt = {
    top: db.prepare<[string, number], HighScore>('SELECT id, initials, score FROM high_scores WHERE board = ? ORDER BY score DESC, id LIMIT ?'),
    add: db.prepare('INSERT INTO high_scores(board, score, initials) VALUES(?, ?, ?)'),
    setScore: db.prepare('UPDATE high_scores SET score = ? WHERE id = ?'),
    setInitials: db.prepare('UPDATE high_scores SET initials = ? WHERE id = ?'),
    remove: db.prepare('DELETE FROM high_scores WHERE id = ?'),
    prune: db.prepare('DELETE FROM high_scores WHERE board = ? AND id NOT IN (SELECT id FROM high_scores WHERE board = ? ORDER BY score DESC, id LIMIT ?)')
  };
  return {
    top: (board, limit) => stmt.top.all(board, limit),
    add: (board, score, initials) => Number(stmt.add.run(board, Math.round(score), initials).lastInsertRowid),
    setScore: (id, score) => void stmt.setScore.run(Math.round(score), id),
    setInitials: (id, initials) => void stmt.setInitials.run(initials, id),
    remove: (id) => stmt.remove.run(id).changes > 0,
    prune: (board, keep) => void stmt.prune.run(board, board, keep)
  };
}
