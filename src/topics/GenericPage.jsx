import GenericTopic from '../components/GenericTopic.jsx';
import { SERVER } from './content/server.js';
import { CLIENT } from './content/client.jsx';
import { ADVANCED } from './content/advanced.js';

const DEFS = { ...SERVER, ...CLIENT, ...ADVANCED };

/** All data-driven topic pages, in one chunk that loads only when a topic is opened. */
export default function GenericPage({ id }) {
  return DEFS[id] ? <GenericTopic key={id} def={{ id, ...DEFS[id] }} /> : null;
}
