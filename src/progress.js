// Per-browser learning progress. Stored locally only; the site works without it.
const KEY = 'htd-visited';

export function getVisited() {
  try {
    return new Set(JSON.parse(localStorage.getItem(KEY) || '[]'));
  } catch {
    return new Set();
  }
}

export function markVisited(id) {
  try {
    const s = getVisited();
    s.add(id);
    localStorage.setItem(KEY, JSON.stringify([...s]));
  } catch {
    /* storage unavailable */
  }
}

export function resetVisited() {
  try {
    localStorage.removeItem(KEY);
  } catch {
    /* storage unavailable */
  }
}

export function getFlag(key) {
  try {
    return localStorage.getItem(key) === '1';
  } catch {
    return false;
  }
}

export function setFlag(key) {
  try {
    localStorage.setItem(key, '1');
  } catch {
    /* storage unavailable */
  }
}

const SOLVED = 'htd-solved';

export function getSolved() {
  try {
    return new Set(JSON.parse(localStorage.getItem(SOLVED) || '[]'));
  } catch {
    return new Set();
  }
}

export function markSolved(id) {
  try {
    const s = getSolved();
    s.add(id);
    localStorage.setItem(SOLVED, JSON.stringify([...s]));
  } catch {
    /* storage unavailable */
  }
}

export function resetSolved() {
  try {
    localStorage.removeItem(SOLVED);
  } catch {
    /* storage unavailable */
  }
}
