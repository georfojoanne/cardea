import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { Shield, Activity, Zap } from 'lucide-react';
import type { AnalyticsResponse, Alert } from './types';

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

  if (!data) return <div className="p-10 bg-slate-900 h-screen">Loading Oracle Data...</div>;

  return (
    <div className="p-8 bg-slate-950 min-h-screen text-slate-100">
      <nav className="flex items-center justify-between mb-10 border-b border-slate-800 pb-5">
        <div className="flex items-center gap-3">
          <Shield className="text-cyan-400 w-8 h-8" />
          <h1 className="text-2xl font-black tracking-tighter">CARDEA <span className="text-cyan-500">ORACLE</span></h1>
        </div>
        <div className="px-4 py-1 rounded-full bg-cyan-950 border border-cyan-800 text-cyan-400 text-sm flex items-center gap-2">
          <div className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse" />
          Azure AI Connected
        </div>
      </nav>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-10">
        <MetricCard title="Total Anomalies" value={data.total_alerts} icon={<Activity />} />
        <MetricCard title="Global Risk Level" value={`${(data.risk_score * 100).toFixed(1)}%`} icon={<Zap />} />
        <MetricCard title="Sentry Status" value="Online" icon={<Shield />} />
      </div>

      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
        <table className="w-full text-left">
          <thead className="bg-slate-800/50 text-slate-400 text-xs font-bold uppercase">
            <tr>
              <th className="p-4">Timestamp</th>
              <th className="p-4">Source</th>
              <th className="p-4">Threat Type</th>
              <th className="p-4">Azure AI Reasoning</th>
            </tr>
          </thead>
          <tbody>
            {data.alerts.map((alert) => (
              <tr key={alert.id} className="border-t border-slate-800 hover:bg-slate-800/30 transition-colors">
                <td className="p-4 text-slate-500 text-sm">
                  {new Date(alert.timestamp).toLocaleTimeString()}
                </td>
                <td className="p-4 font-mono text-cyan-200">{alert.source}</td>
                <td className="p-4">
                  <span className={`px-2 py-0.5 rounded text-xs font-bold ${getSeverityClass(alert.severity)}`}>
                    {alert.alert_type}
                  </span>
                </td>
                <td className="p-4 text-slate-300 max-w-md truncate">{alert.description}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

const getSeverityClass = (severity: string) => {
  if (severity === 'high' || severity === 'critical') return 'bg-red-950 text-red-400 border border-red-800';
  return 'bg-yellow-950 text-yellow-400 border border-yellow-800';
};

const MetricCard: React.FC<{ title: string, value: string | number, icon: React.ReactNode }> = ({ title, value, icon }) => (
  <div className="bg-slate-900 p-6 rounded-xl border border-slate-800 shadow-xl">
    <div className="flex justify-between items-center mb-2">
      <h3 className="text-slate-500 font-bold uppercase text-xs tracking-widest">{title}</h3>
      <div className="text-cyan-500 opacity-50">{icon}</div>
    </div>
    <p className="text-4xl font-extrabold">{value}</p>
  </div>
);

export default App;