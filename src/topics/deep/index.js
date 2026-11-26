import { CORE1 } from './core1.js';
import { CORE2 } from './core2.js';
import { SERVER2A } from './server2a.js';
import { SERVER2B } from './server2b.js';
import { CLIENT3 } from './client3.js';

export const DEEP = { ...CORE1, ...CORE2, ...SERVER2A, ...SERVER2B, ...CLIENT3 };
