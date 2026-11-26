import { CORE1 } from './core1.js';
import { CORE2 } from './core2.js';
import { SERVER2A } from './server2a.js';
import { SERVER2B } from './server2b.js';
import { CLIENT3 } from './client3.js';
import { ADV4A } from './adv4a.js';
import { ADV4B } from './adv4b.js';

/** Variants, challenges and real-world cases for every topic, keyed by topic id. */
export const DEEP = { ...CORE1, ...CORE2, ...SERVER2A, ...SERVER2B, ...CLIENT3, ...ADV4A, ...ADV4B };
