/** Dormancy days of Admin > Identity rules: a whole number within the server's bounds (the server checks again). */
export function parseDays(v: string): number {
  return /^\d+$/.test(v.trim()) ? Number(v) : NaN;
}

export function daysOk(n: number, min: number, max: number): boolean {
  return n >= min && n <= max;
}
