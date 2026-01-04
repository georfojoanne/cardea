import { useState, useEffect } from 'react';
import axios from 'axios';
import { Shield, Activity, Zap, Server } from 'lucide-react';
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
      {/* Clean, Plain Header */}
      <header className="border-b border-slate-900 bg-slate-950/50 backdrop-blur-md sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-6 py-4 flex justify-between items-center">
          <div className="flex items-center gap-2">
            <Shield className="w-5 h-5 text-cyan-500" />
            <span className="font-bold tracking-tight text-lg">
              CARDEA <span className="text-slate-500 font-light">ORACLE</span>
            </span>
          </div>
          <div className="flex items-center gap-6 text-[10px] font-bold text-slate-500 tracking-widest">
            <span className="flex items-center gap-1.5">
              <div className="w-1.5 h-1.5 rounded-full bg-green-500 animate-pulse" /> 
              CLOUD ENGINE ONLINE
            </span>
            <span className="flex items-center gap-1.5">
              <div className="w-1.5 h-1.5 rounded-full bg-cyan-500" /> 
              SENTRY: X230-ARCH
            </span>
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-6 py-10 space-y-6">
        
        {/* TOP ROW: Visualization & High-Level Metrics */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="lg:col-span-2">
            <NetworkMap />
          </div>
          
          <div className="flex flex-col gap-6">
            <div className="bg-slate-900/40 border border-slate-900 p-6 rounded-xl flex-1 flex flex-col justify-center">
              <div className="flex items-center gap-2 text-slate-500 mb-2">
                <Zap className="w-3 h-3 text-cyan-500" />
                <p className="text-[10px] font-bold uppercase tracking-wider">Risk Index</p>
              </div>
              <p className="text-5xl font-extralight text-cyan-400">
                {(data.risk_score * 100).toFixed(1)}%
              </p>
              <p className="text-[10px] text-slate-600 mt-4 leading-relaxed font-medium">
                AGGREGATED THREAT LEVEL CALCULATED VIA AGENTIC REASONING (GPT-4O).
              </p>
            </div>
            
            <div className="bg-slate-900/40 border border-slate-900 p-6 rounded-xl flex-1 flex flex-col justify-center">
              <div className="flex items-center gap-2 text-slate-500 mb-2">
                <Activity className="w-3 h-3 text-purple-500" />
                <p className="text-[10px] font-bold uppercase tracking-wider">Total Events</p>
              </div>
              <p className="text-5xl font-extralight">{data.total_alerts}</p>
              <p className="text-[10px] text-slate-600 mt-4 leading-relaxed font-medium">
                PACKETS ANALYZED BY KITNET & ESCALATED BY SENTRY BRIDGE.
              </p>
            </div>
          </div>
        </div>

        {/* BOTTOM ROW: Alert Feed Table */}
        <div className="bg-slate-900/20 border border-slate-900 rounded-xl overflow-hidden">
          <div className="px-6 py-4 border-b border-slate-900 bg-slate-900/40 flex items-center gap-2">
            <Server className="w-4 h-4 text-slate-500" />
            <h2 className="text-xs font-bold uppercase tracking-widest text-slate-400">Live Anomaly Feed</h2>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="text-slate-600 text-[10px] uppercase tracking-widest border-b border-slate-900/50">
                  <th className="px-6 py-4 font-bold">Time</th>
                  <th className="px-6 py-4 font-bold">Event Details</th>
                  <th className="px-6 py-4 font-bold">Source Node</th>
                  <th className="px-6 py-4 font-bold text-right">Severity</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-900/50">
                {data.alerts.map((alert: Alert) => (
                  <tr key={alert.id} className="hover:bg-slate-900/40 transition-colors group">
                    <td className="px-6 py-5 text-xs text-slate-500 font-mono tabular-nums">
                      {new Date(alert.timestamp).toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                    </td>
                    <td className="px-6 py-5">
                      <p className="text-sm font-semibold text-slate-300 group-hover:text-cyan-400 transition-colors">
                        {alert.alert_type.replace('_', ' ').toUpperCase()}
                      </p>
                      <p className="text-xs text-slate-500 mt-0.5 line-clamp-1">{alert.description}</p>
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
                ))}
              </tbody>
            </table>
          </div>
          {data.alerts.length === 0 && (
            <div className="p-20 text-center text-slate-700 text-xs font-mono italic">
              NO ANOMALIES DETECTED IN CURRENT TIME WINDOW
            </div>
          )}
        </div>
      </main>
    </div>
  );
};

export default App;