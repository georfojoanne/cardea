import { useState, useEffect } from 'react';
import axios from 'axios';
import { Shield, Activity, Zap, Server, AlertCircle } from 'lucide-react';
import type { AnalyticsResponse, Alert } from './types'; 
import { NetworkMap } from './components/NetworkMap';

const ORACLE_URL = "http://localhost:8000";

const App: React.FC = () => {
  const [data, setData] = useState<AnalyticsResponse | null>(null);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const res = await axios.get<AnalyticsResponse>(`${ORACLE_URL}/api/analytics`);
        setData(res.data);
      } catch (err) {
        console.error("Oracle API Error:", err);
      }
    };

    fetchData();
    const interval = setInterval(fetchData, 5000);
    return () => clearInterval(interval);
  }, []);

  if (!data) return (
    <div className="flex items-center justify-center h-screen bg-slate-950 text-slate-600 font-mono text-sm tracking-tighter">
      <div className="flex flex-col items-center gap-4">
        <div className="w-5 h-5 border-2 border-cyan-500 border-t-transparent rounded-full animate-spin" />
        INITIALIZING CARDEA ORACLE CONNECTION...
      </div>
    </div>
  );

  return (
    <div className="min-h-screen bg-slate-950 text-slate-200 font-sans selection:bg-cyan-500/30">
      <header className="border-b border-slate-900 bg-slate-950/50 backdrop-blur-md sticky top-0 z-50 px-6 py-4">
        <div className="max-w-7xl mx-auto flex justify-between items-center">
          <div className="flex items-center gap-2">
            <Shield className="w-5 h-5 text-cyan-500" />
            <span className="font-bold tracking-tight text-lg">
              CARDEA <span className="text-slate-500 font-light">ORACLE</span>
            </span>
          </div>
          <div className="flex items-center gap-6 text-[10px] font-bold text-slate-500 tracking-widest uppercase">
            <span className="flex items-center gap-1.5">
              <div className="w-1.5 h-1.5 rounded-full bg-green-500 animate-pulse" /> 
              Cloud Link: Verified
            </span>
            <span className="flex items-center gap-1.5">
              <div className="w-1.5 h-1.5 rounded-full bg-cyan-500" /> 
              Node: X230-ARCH
            </span>
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-6 py-10 space-y-6">
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="lg:col-span-2">
            <NetworkMap />
          </div>
          
          <div className="flex flex-col gap-6">
            <div className="bg-slate-900/40 border border-slate-900 p-6 rounded-xl flex-1 flex flex-col justify-center relative overflow-hidden">
              <div className="absolute top-0 right-0 p-2 opacity-10">
                <Zap className="w-20 h-20 text-cyan-400" />
              </div>
              <div className="flex items-center gap-2 text-slate-500 mb-2 relative z-10">
                <Zap className="w-3 h-3 text-cyan-500" />
                <p className="text-[10px] font-bold uppercase tracking-wider">Risk Index</p>
              </div>
              <p className="text-5xl font-extralight text-cyan-400 relative z-10">
                {((data?.risk_score || 0) * 100).toFixed(1)}%
              </p>
              <p className="text-[10px] text-slate-600 mt-4 leading-relaxed font-medium uppercase tracking-tighter">
                Azure OpenAI Agentic Reasoning Active
              </p>
            </div>
            
            <div className="bg-slate-900/40 border border-slate-900 p-6 rounded-xl flex-1 flex flex-col justify-center">
              <div className="flex items-center gap-2 text-slate-500 mb-2">
                <Activity className="w-3 h-3 text-purple-500" />
                <p className="text-[10px] font-bold uppercase tracking-wider">Telemetry Events</p>
              </div>
              <p className="text-5xl font-extralight">{data.total_alerts || 0}</p>
              <p className="text-[10px] text-slate-600 mt-4 leading-relaxed font-medium uppercase tracking-tighter">
                Real-time Ingestion via Sentry-Pipe
              </p>
            </div>
          </div>
        </div>

        <div className="bg-slate-900/20 border border-slate-900 rounded-xl overflow-hidden shadow-2xl">
          <div className="px-6 py-4 border-b border-slate-900 bg-slate-900/40 flex items-center justify-between">
            <div className="flex items-center gap-2">
                <Server className="w-4 h-4 text-slate-500" />
                <h2 className="text-xs font-bold uppercase tracking-widest text-slate-400">Live Anomaly Feed</h2>
            </div>
            <div className="text-[8px] font-mono text-slate-600 uppercase tracking-widest">
                Updates: Auto (5s)
            </div>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="text-slate-600 text-[10px] uppercase tracking-widest border-b border-slate-900/50">
                  <th className="px-6 py-4 font-bold">Timestamp</th>
                  <th className="px-6 py-4 font-bold">Alert Signature</th>
                  <th className="px-6 py-4 font-bold">Node Source</th>
                  <th className="px-6 py-4 font-bold text-right">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-900/50">
                {/* SAFE MAPPING: Checks alerts exists and has content */}
                {data.alerts && data.alerts.length > 0 ? (
                  data.alerts.map((alert: Alert) => (
                    <tr key={alert.id} className="hover:bg-slate-900/40 transition-colors group">
                      <td className="px-6 py-5 text-xs text-slate-500 font-mono tabular-nums">
                        {new Date(alert.timestamp).toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                      </td>
                      <td className="px-6 py-5">
                        <p className="text-sm font-semibold text-slate-300 group-hover:text-cyan-400 transition-colors">
                          {(alert.alert_type || 'Unknown').replace('_', ' ').toUpperCase()}
                        </p>
                        <p className="text-xs text-slate-500 mt-0.5 line-clamp-1 italic">"{alert.description}"</p>
                      </td>
                      <td className="px-6 py-5 text-xs font-mono text-slate-400">
                        {alert.source}
                      </td>
                      <td className="px-6 py-5 text-right">
                        <span className={`text-[9px] font-black px-2.5 py-1 rounded border tracking-tighter ${
                          alert.severity === 'high' || alert.severity === 'critical' 
                          ? 'border-red-900/50 bg-red-950/20 text-red-500' 
                          : 'border-cyan-900/50 bg-cyan-950/20 text-cyan-500'
                        }`}>
                          {alert.severity.toUpperCase()}
                        </span>
                      </td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan={4} className="p-24 text-center">
                      <div className="flex flex-col items-center gap-3 opacity-20">
                        <AlertCircle className="w-10 h-10" />
                        <p className="text-[10px] font-mono tracking-widest uppercase">
                          No tactical anomalies detected in current buffer
                        </p>
                      </div>
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      </main>
    </div>
  );
};

export default App;