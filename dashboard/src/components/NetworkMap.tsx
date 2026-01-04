import { ReactFlow, Background, BackgroundVariant } from '@xyflow/react';
import type { Edge, Node } from '@xyflow/react';
import '@xyflow/react/dist/style.css';

const initialNodes: Node[] = [
  { 
    id: 'sentry', 
    type: 'input',
    data: { label: 'X230-ARCH [EDGE]' }, 
    position: { x: 0, y: 0 },
    className: 'bg-slate-950 text-cyan-500 border-2 border-cyan-900 rounded-md p-3 text-[10px] font-mono shadow-[0_0_15px_rgba(6,182,212,0.1)] w-40'
  },
  { 
    id: 'oracle', 
    type: 'output',
    data: { label: 'AZURE-ORACLE [CLOUD]' }, 
    position: { x: 350, y: 0 },
    className: 'bg-slate-950 text-purple-500 border-2 border-purple-900 rounded-md p-3 text-[10px] font-mono shadow-[0_0_15px_rgba(168,85,247,0.1)] w-40'
  },
];

const initialEdges: Edge[] = [
  { 
    id: 'e1-2', 
    source: 'sentry', 
    target: 'oracle', 
    animated: true, 
    style: { stroke: '#06b6d4', strokeWidth: 2 } 
  }
];

export const NetworkMap = () => {
  return (
    <div className="h-full w-full min-h-[350px] bg-[#020617] rounded-xl border border-slate-900 overflow-hidden relative shadow-inner">
      <ReactFlow 
        nodes={initialNodes} 
        edges={initialEdges}
        fitView
        colorMode="dark"
        // Disables interactions to make it feel like a read-only monitoring map
        nodesDraggable={false}
        nodesConnectable={false}
        elementsSelectable={false}
      >
        {/* FIX: Using BackgroundVariant enum to satisfy TypeScript */}
        <Background color="#0f172a" variant={BackgroundVariant.Lines} gap={25} />
      </ReactFlow>
      
      {/* Tactical Overlays */}
      <div className="absolute top-4 left-4 flex flex-col gap-1 text-[8px] font-bold uppercase tracking-widest text-slate-600">
        <span>Region: East-Asia-01</span>
        <span>Secure Tunnel: v4.22-Stable</span>
      </div>

      <div className="absolute bottom-4 left-4 flex gap-4 text-[9px] font-bold uppercase tracking-tighter text-slate-500 bg-slate-950/80 px-2 py-1 rounded border border-slate-900">
        <span className="flex items-center gap-1">
            <div className="w-1.5 h-1.5 bg-cyan-500 rounded-full animate-pulse" /> 
            Link: Active
        </span>
        <span className="flex items-center gap-1">
            <div className="w-1.5 h-1.5 bg-slate-700 rounded-full" /> 
            Latency: 24ms
        </span>
      </div>
    </div>
  );
};