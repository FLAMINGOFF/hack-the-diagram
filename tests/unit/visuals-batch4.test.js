import { describe, expect, it } from 'vitest';
import * as b from '../../src/visuals/batch4.js';

const only = (fn, attack, defences) => Object.fromEntries(Object.keys(defences).map((k) => [k, fn(attack, { [k]: true }).outcome]));

describe('LLM prompt injection', () => {
  it('a prompt-only defence never counts as a fix', () => {
    for (const a of Object.keys(b.LLM_ATTACKS)) expect(b.llmTurn(a, { delimit: true }).outcome).toBe('pwned');
  });
  it('code-level controls stop the attack they cover', () => {
    expect(only(b.llmTurn, 'delete', b.LLM_DEFENCES)).toEqual({ delimit: 'pwned', confirm: 'blocked', least: 'blocked', noimg: 'pwned' });
    expect(only(b.llmTurn, 'exfil', b.LLM_DEFENCES)).toEqual({ delimit: 'pwned', confirm: 'pwned', least: 'pwned', noimg: 'blocked' });
  });
});

describe('MCP tool poisoning', () => {
  it('reviewing at install catches poisoning but not a later rug pull', () => {
    expect(only(b.mcpRun, 'poison', b.MCP_DEFENCES)).toEqual({ review: 'blocked', pin: 'pwned', scope: 'blocked' });
    expect(only(b.mcpRun, 'rugpull', b.MCP_DEFENCES)).toEqual({ review: 'pwned', pin: 'blocked', scope: 'blocked' });
  });
});

describe('cache poisoning', () => {
  it('needs an input that is both unkeyed and reflected', () => {
    for (const a of Object.keys(b.CP_ATTACKS)) {
      expect(b.poison(a, {}).outcome).toBe('pwned');
      expect(b.poison(a, { key: true }).outcome).toBe('blocked');
      expect(b.poison(a, { ignore: true }).outcome).toBe('blocked');
    }
  });
});

describe('Host header reset poisoning', () => {
  it('a Host allowlist misses X-Forwarded-Host, a configured base URL does not', () => {
    expect(only(b.resetPoison, 'host', b.HH_DEFENCES)).toEqual({ allow: 'blocked', config: 'blocked' });
    expect(only(b.resetPoison, 'xfh', b.HH_DEFENCES)).toEqual({ allow: 'pwned', config: 'blocked' });
    expect(b.resetPoison('xfh', {}).link).toContain('evil.example');
  });
});

describe('prototype pollution (simulated)', () => {
  it('skipping only __proto__ is bypassed by constructor.prototype', () => {
    expect(b.ppMerge('proto', 'none').polluted).toBe(true);
    expect(b.ppMerge('ctor', 'none').polluted).toBe(true);
    expect(b.ppMerge('proto', 'blockProto').polluted).toBe(false);
    expect(b.ppMerge('ctor', 'blockProto').polluted).toBe(true);
  });
  it('blocking all three keys or freezing the prototype stops both', () => {
    for (const a of Object.keys(b.PP_ATTACKS)) {
      expect(b.ppMerge(a, 'blockAll').polluted).toBe(false);
      expect(b.ppMerge(a, 'freeze').polluted).toBe(false);
    }
  });
  it('never touches the real Object.prototype', () => {
    for (const a of Object.keys(b.PP_ATTACKS)) for (const d of Object.keys(b.PP_DEFENCES)) b.ppMerge(a, d);
    expect({}.isAdmin).toBeUndefined();
    expect(Object.prototype).not.toHaveProperty('isAdmin');
  });
});
