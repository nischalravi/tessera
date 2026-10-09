/**
 * Small fuzzy matcher for the command palette and global search.
 * Every query character must appear in order. Matches at word starts and runs of
 * consecutive characters score higher; shorter targets win ties.
 */
export interface Match { score: number; indices: number[] }

export function fuzzy(query: string, target: string): Match | null {
  const q = query.toLowerCase().replace(/\s+/g, " ").trim();
  if (!q) return { score: 0, indices: [] };
  const t = target.toLowerCase();
  // fast path: plain substring is the strongest signal
  const sub = t.indexOf(q);
  if (sub >= 0) {
    const atWord = sub === 0 || /[\s\-_:./@(]/.test(t[sub - 1]);
    return { score: 1000 - sub - t.length * 0.1 + (atWord ? 200 : 0), indices: Array.from({ length: q.length }, (_, i) => sub + i) };
  }
  const indices: number[] = [];
  let score = 0, ti = 0, prev = -2;
  for (const ch of q) {
    if (ch === " ") continue;
    const found = t.indexOf(ch, ti);
    if (found < 0) return null;
    const wordStart = found === 0 || /[\s\-_:./@(]/.test(t[found - 1]);
    score += (found === prev + 1 ? 12 : 0) + (wordStart ? 10 : 0) - Math.min(found - ti, 8);
    indices.push(found);
    prev = found;
    ti = found + 1;
  }
  return { score: score - t.length * 0.1, indices };
}

/** Best match over a label (full weight) and extra keywords (lower weight, no highlight). */
export function rank(query: string, label: string, keywords?: string): Match | null {
  const a = fuzzy(query, label);
  if (a) return a;
  if (!keywords) return null;
  const b = fuzzy(query, keywords);
  return b ? { score: b.score * 0.6 - 50, indices: [] } : null;
}
