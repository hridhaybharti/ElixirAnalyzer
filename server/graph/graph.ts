import fs from 'fs';
import path from 'path';

export type NodeId = string; // e.g., url:https://..., domain:example.com, ip:1.2.3.4
export interface Edge { from: NodeId; to: NodeId; type: string; ts: number }

const graphDir = path.resolve(process.cwd(), 'server', 'data', 'graph');
const graphFile = path.join(graphDir, 'graph.json');

function ensure() {
  if (!fs.existsSync(graphDir)) fs.mkdirSync(graphDir, { recursive: true });
  if (!fs.existsSync(graphFile)) fs.writeFileSync(graphFile, JSON.stringify({ edges: [] }), 'utf-8');
}

function readAll(): { edges: Edge[] } {
  ensure();
  try { return JSON.parse(fs.readFileSync(graphFile, 'utf-8')); } catch { return { edges: [] }; }
}

function writeAll(data: { edges: Edge[] }) {
  ensure();
  fs.writeFileSync(graphFile, JSON.stringify(data, null, 2), 'utf-8');
}

export const GraphService = {
  addEdge(from: NodeId, to: NodeId, type: string) {
    const g = readAll();
    const key = `${from}::${to}::${type}`;
    const exists = g.edges.some(e => `${e.from}::${e.to}::${e.type}` === key);
    if (!exists) {
      g.edges.push({ from, to, type, ts: Date.now() });
      writeAll(g);
    }
  },
  neighbors(node: NodeId) {
    const g = readAll();
    const out: Edge[] = g.edges.filter(e => e.from === node || e.to === node);
    return out;
  },
  subgraph(center: NodeId, depth = 1) {
    const g = readAll();
    const seen = new Set<NodeId>([center]);
    const edges: Edge[] = [];
    let frontier = [center];
    for (let d = 0; d < depth; d++) {
      const next: NodeId[] = [];
      for (const n of frontier) {
        for (const e of g.edges) {
          if (e.from === n || e.to === n) {
            edges.push(e);
            const other = e.from === n ? e.to : e.from;
            if (!seen.has(other)) { seen.add(other); next.push(other); }
          }
        }
      }
      frontier = next;
    }
    return { center, nodes: Array.from(seen), edges };
  }
};
