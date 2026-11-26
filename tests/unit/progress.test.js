import { beforeEach, describe, expect, it } from 'vitest';
import { getSolved, getVisited, markSolved, markVisited, resetSolved, resetVisited } from '../../src/progress.js';

describe('local progress', () => {
  beforeEach(() => localStorage.clear());

  it('remembers visited topics and solved challenges, and resets them', () => {
    markVisited('xss');
    markSolved('xss:1');
    markSolved('xss:1');
    expect([...getVisited()]).toEqual(['xss']);
    expect([...getSolved()]).toEqual(['xss:1']);
    resetVisited();
    resetSolved();
    expect(getVisited().size + getSolved().size).toBe(0);
  });

  it('treats corrupted storage as empty', () => {
    localStorage.setItem('htd-solved', '{not json');
    expect(getSolved().size).toBe(0);
  });
});
