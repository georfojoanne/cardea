import { useState, useEffect, useCallback } from 'react';
import axios from 'axios';
import { 
  Shield, Activity, Zap, Server, AlertCircle, AlertTriangle, Info, XCircle,
  Brain, Sparkles, CheckCircle2, WifiOff, RefreshCw, Lightbulb, TrendingUp
} from 'lucide-react';
import type { AnalyticsResponse, Alert, AIInsight } from './types'; 
import { ThreatOverview } from './components/ThreatOverview';

// Use environment variable or default to localhost for development
const ORACLE_URL = import.meta.env.VITE_ORACLE_URL || "http://localhost:8000";

// Severity color/icon mapping
const severityConfig = {
  critical: { color: 'text-red-500', bg: 'bg-red-950/20 border-red-900/50', icon: XCircle },
  high: { color: 'text-orange-500', bg: 'bg-orange-950/20 border-orange-900/50', icon: AlertTriangle },
  medium: { color: 'text-yellow-500', bg: 'bg-yellow-950/20 border-yellow-900/50', icon: AlertCircle },
  low: { color: 'text-cyan-500', bg: 'bg-cyan-950/20 border-cyan-900/50', icon: Info },
};

// Toast notification component
const Toast: React.FC<{ message: string; type: 'error' | 'warning' | 'info'; onDismiss: () => void }> = ({ message, type, onDismiss }) => {
  const config = {
    error: { bg: 'bg-red-950/90 border-red-800', icon: XCircle, iconColor: 'text-red-400' },
    warning: { bg: 'bg-yellow-950/90 border-yellow-800', icon: AlertTriangle, iconColor: 'text-yellow-400' },
    info: { bg: 'bg-cyan-950/90 border-cyan-800', icon: Info, iconColor: 'text-cyan-400' },
  }[type];
  const Icon = config.icon;

  return (
    <div className={`fixed bottom-6 right-6 z-50 ${config.bg} border rounded-lg shadow-2xl p-4 max-w-md animate-in slide-in-from-bottom-4 fade-in duration-300`}>
      <div className="flex items-start gap-3">
        <Icon className={`w-5 h-5 ${config.iconColor} flex-shrink-0 mt-0.5`} />
        <div className="flex-1">
          <p className="text-sm text-slate-200 font-medium">{message}</p>
          <p className="text-xs text-slate-400 mt-1">Automatic retry in progress...</p>
        </div>
        <button onClick={onDismiss} className="text-slate-500 hover:text-slate-300 transition-colors">
          <XCircle className="w-4 h-4" />
        </button>
      </div>
    </div>
  );
};

// AI Insight Card Component - The hero component users see first
const AIInsightCard: React.FC<{ insight: AIInsight | null | undefined; isLoading: boolean }> = ({ insight, isLoading }) => {
  if (isLoading) {
    return (
      <div className="bg-gradient-to-br from-slate-900/80 via-slate-900/60 to-cyan-950/30 border border-slate-800 rounded-2xl p-8 animate-pulse">
        <div className="flex items-center gap-3 mb-6">
          <div className="w-10 h-10 rounded-full bg-slate-800" />
          <div className="h-6 w-48 bg-slate-800 rounded" />
        </div>
        <div className="space-y-3">
          <div className="h-4 bg-slate-800 rounded w-full" />
          <div className="h-4 bg-slate-800 rounded w-5/6" />
          <div className="h-4 bg-slate-800 rounded w-4/6" />
        </div>
      </div>
    );
  }

  if (!insight) {
    return (
      <div className="bg-gradient-to-br from-slate-900/80 via-slate-900/60 to-slate-800/30 border border-slate-800 rounded-2xl p-8">
        <div className="flex items-center gap-3 mb-4">
          <div className="p-2.5 bg-slate-800/50 rounded-xl">
            <Brain className="w-6 h-6 text-slate-500" />
          </div>
          <div>
            <h2 className="text-lg font-semibold text-slate-400">AI Security Analysis</h2>
            <p className="text-xs text-slate-600">Waiting for data...</p>
          </div>
        </div>
        <p className="text-slate-500 text-sm leading-relaxed">
          Connect to Oracle backend to receive AI-powered security insights and recommendations.
        </p>
      </div>
    );
  }

  return (
    <div className="bg-gradient-to-br from-slate-900/80 via-cyan-950/20 to-purple-950/20 border border-cyan-900/30 rounded-2xl p-8 relative overflow-hidden">
      {/* Background decoration */}
      <div className="absolute top-0 right-0 opacity-5">
        <Sparkles className="w-40 h-40 text-cyan-400" />
      </div>
      
      {/* Header */}
      <div className="flex items-start justify-between mb-6 relative z-10">
        <div className="flex items-center gap-3">
          <div className="p-2.5 bg-gradient-to-br from-cyan-500/20 to-purple-500/20 rounded-xl border border-cyan-500/20">
            <Brain className="w-6 h-6 text-cyan-400" />
          </div>
          <div>
            <h2 className="text-lg font-semibold text-slate-100">AI Security Analysis</h2>
            <div className="flex items-center gap-2 mt-0.5">
              {insight.ai_powered ? (
                <span className="flex items-center gap-1 text-[10px] text-cyan-400 font-medium">
                  <Sparkles className="w-3 h-3" /> Azure AI Powered
                </span>
              ) : (
                <span className="flex items-center gap-1 text-[10px] text-slate-500 font-medium">
                  <TrendingUp className="w-3 h-3" /> Rule-Based Analysis
                </span>
              )}
              <span className="text-slate-700">•</span>
              <span className="text-[10px] text-slate-500">
                Confidence: {(insight.confidence * 100).toFixed(0)}%
              </span>
            </div>
          </div>
        </div>
        <span className="text-[10px] text-slate-600 font-mono">
          {insight.generated_at ? new Date(insight.generated_at).toLocaleTimeString([], { hour12: false }) : '--:--:--'}
        </span>
      </div>

      {/* Summary - The main message */}
      <div className="mb-6 relative z-10">
        <p className="text-xl font-light text-slate-100 leading-relaxed">
          {insight.summary}
        </p>
      </div>

      {/* What Happened & Why It Matters */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6 relative z-10">
        <div className="bg-slate-900/50 rounded-xl p-4 border border-slate-800/50">
          <div className="flex items-center gap-2 mb-2">
            <AlertCircle className="w-4 h-4 text-orange-400" />
            <h3 className="text-xs font-bold text-slate-400 uppercase tracking-wider">What Happened</h3>
          </div>
          <p className="text-sm text-slate-300 leading-relaxed">{insight.what_happened}</p>
        </div>
        <div className="bg-slate-900/50 rounded-xl p-4 border border-slate-800/50">
          <div className="flex items-center gap-2 mb-2">
            <Lightbulb className="w-4 h-4 text-yellow-400" />
            <h3 className="text-xs font-bold text-slate-400 uppercase tracking-wider">Why It Matters</h3>
          </div>
          <p className="text-sm text-slate-300 leading-relaxed">{insight.why_it_matters}</p>
        </div>
      </div>

      {/* Recommended Actions */}
      <div className="relative z-10">
        <div className="flex items-center gap-2 mb-3">
          <CheckCircle2 className="w-4 h-4 text-green-400" />
          <h3 className="text-xs font-bold text-slate-400 uppercase tracking-wider">Recommended Actions</h3>
        </div>
        <ul className="space-y-2">
          {insight.recommended_actions.map((action, index) => (
            <li key={index} className="flex items-start gap-3 text-sm text-slate-300">
              <span className="flex-shrink-0 w-5 h-5 bg-cyan-500/10 border border-cyan-500/30 rounded-full flex items-center justify-center text-[10px] font-bold text-cyan-400">
                {index + 1}
              </span>
              <span className="leading-relaxed">{action}</span>
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
};

// Empty State Component
const EmptyState: React.FC<{ title: string; description: string; icon?: React.ElementType }> = ({ 
  title, 
  description, 
  icon: Icon = AlertCircle 
}) => (
  <div className="flex flex-col items-center justify-center py-16 px-8">
    <div className="p-4 bg-slate-900/50 rounded-2xl mb-4">
      <Icon className="w-12 h-12 text-slate-600" />
    </div>
    <h3 className="text-lg font-medium text-slate-400 mb-2">{title}</h3>
    <p className="text-sm text-slate-600 text-center max-w-md">{description}</p>
  </div>
);

// Connection Status Component
const ConnectionStatus: React.FC<{ isConnected: boolean; isRetrying: boolean }> = ({ isConnected, isRetrying }) => (
  <span className="flex items-center gap-1.5">
    {isConnected ? (
      <>
        <div className="w-1.5 h-1.5 rounded-full bg-green-500 animate-pulse" />
        <span className="text-green-500/70">Oracle: Connected</span>
      </>
    ) : (
      <>
        {isRetrying ? (
          <RefreshCw className="w-3 h-3 text-yellow-500 animate-spin" />
        ) : (
          <WifiOff className="w-3 h-3 text-red-500" />
        )}
        <span className={isRetrying ? "text-yellow-500/70" : "text-red-500/70"}>
          {isRetrying ? "Reconnecting..." : "Oracle: Offline"}
        </span>
      </>
    )}
  </span>
);

const App: React.FC = () => {
  const [data, setData] = useState<AnalyticsResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [lastUpdate, setLastUpdate] = useState<Date | null>(null);
  const [isConnected, setIsConnected] = useState<boolean>(false);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [showToast, setShowToast] = useState<boolean>(false);
  const [retryCount, setRetryCount] = useState<number>(0);

  const fetchData = useCallback(async () => {
    try {
      const res = await axios.get<AnalyticsResponse>(`${ORACLE_URL}/api/analytics`, {
        timeout: 10000, // 10 second timeout
      });
      setData(res.data);
      setError(null);
      setIsConnected(true);
      setLastUpdate(new Date());
      setShowToast(false);
      setRetryCount(0);
    } catch (err) {
      console.error("Oracle API Error:", err);
      setIsConnected(false);
      setRetryCount(prev => prev + 1);
      
      // Only show toast on first few failures, then just silently retry
      if (retryCount < 3) {
        setError("Unable to connect to Cardea Oracle backend");
        setShowToast(true);
      }
    } finally {
      setIsLoading(false);
    }
  }, [retryCount]);

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 5000);
    return () => clearInterval(interval);
  }, [fetchData]);

  // Calculate severity stats for display
  const severityStats = data?.alerts_by_severity || {};
  const criticalCount = severityStats['critical'] || 0;
  const highCount = severityStats['high'] || 0;

  return (
    <div className="min-h-screen bg-slate-950 text-slate-200 font-sans selection:bg-cyan-500/30">
      {/* Toast Notification */}
      {showToast && error && (
        <Toast 
          message={error} 
          type="error" 
          onDismiss={() => setShowToast(false)} 
        />
      )}

      <header className="border-b border-slate-900 bg-slate-950/50 backdrop-blur-md sticky top-0 z-50 px-6 py-4">
        <div className="max-w-7xl mx-auto flex justify-between items-center">
          <div className="flex items-center gap-2">
            <Shield className="w-5 h-5 text-cyan-500" />
            <span className="font-bold tracking-tight text-lg">
              CARDEA <span className="text-slate-500 font-light">ORACLE</span>
            </span>
          </div>
          <div className="flex items-center gap-6 text-[10px] font-bold text-slate-500 tracking-widest uppercase">
            {isConnected && (criticalCount > 0 || highCount > 0) && (
              <span className="flex items-center gap-1.5 text-red-500">
                <AlertTriangle className="w-3 h-3" />
                {criticalCount + highCount} Critical/High Alerts
              </span>
            )}
            <ConnectionStatus isConnected={isConnected} isRetrying={!isConnected && retryCount > 0} />
            {lastUpdate && isConnected && (
              <span className="text-slate-600">
                Updated: {lastUpdate.toLocaleTimeString([], { hour12: false })}
              </span>
            )}
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-6 py-10 space-y-6">
        {/* AI INSIGHT CARD - First thing users see */}
        <AIInsightCard insight={data?.ai_insight} isLoading={isLoading && !data} />

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="lg:col-span-2">
            <ThreatOverview 
              alerts={data?.alerts || []} 
              severityStats={severityStats}
              isConnected={isConnected}
            />
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
              {isConnected && data ? (
                <>
                  <p className={`text-5xl font-extralight relative z-10 ${
                    (data?.risk_score || 0) >= 0.7 ? 'text-red-400' : 
                    (data?.risk_score || 0) >= 0.4 ? 'text-yellow-400' : 'text-cyan-400'
                  }`}>
                    {((data?.risk_score || 0) * 100).toFixed(1)}%
                  </p>
                  <p className="text-[10px] text-slate-600 mt-4 leading-relaxed font-medium uppercase tracking-tighter">
                    AI-Powered Threat Analysis
                  </p>
                </>
              ) : (
                <p className="text-5xl font-extralight text-slate-700 relative z-10">—</p>
              )}
            </div>
            
            <div className="bg-slate-900/40 border border-slate-900 p-6 rounded-xl flex-1 flex flex-col justify-center">
              <div className="flex items-center gap-2 text-slate-500 mb-2">
                <Activity className="w-3 h-3 text-purple-500" />
                <p className="text-[10px] font-bold uppercase tracking-wider">Telemetry Events</p>
              </div>
              {isConnected && data ? (
                <>
                  <p className="text-5xl font-extralight">{data.total_alerts || 0}</p>
                  
                  {/* Severity Breakdown */}
                  {Object.keys(severityStats).length > 0 && (
                    <div className="flex gap-3 mt-4">
                      {Object.entries(severityStats).map(([severity, count]) => {
                        const config = severityConfig[severity as keyof typeof severityConfig] || severityConfig.low;
                        return (
                          <div key={severity} className={`flex items-center gap-1 text-[9px] ${config.color}`}>
                            <span className="font-bold">{count}</span>
                            <span className="uppercase opacity-70">{severity}</span>
                          </div>
                        );
                      })}
                    </div>
                  )}
                </>
              ) : (
                <p className="text-5xl font-extralight text-slate-700">—</p>
              )}
            </div>
          </div>
        </div>

        <div className="bg-slate-900/20 border border-slate-900 rounded-xl overflow-hidden shadow-2xl">
          <div className="px-6 py-4 border-b border-slate-900 bg-slate-900/40 flex items-center justify-between">
            <div className="flex items-center gap-2">
                <Server className="w-4 h-4 text-slate-500" />
                <h2 className="text-xs font-bold uppercase tracking-widest text-slate-400">Live Anomaly Feed</h2>
            </div>
            <div className="flex items-center gap-4">
              <div className="text-[8px] font-mono text-slate-600 uppercase tracking-widest">
                  Showing latest 50 alerts
              </div>
              <div className="text-[8px] font-mono text-slate-600 uppercase tracking-widest">
                  Updates: Auto (5s)
              </div>
            </div>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="text-slate-600 text-[10px] uppercase tracking-widest border-b border-slate-900/50">
                  <th className="px-6 py-4 font-bold">Timestamp</th>
                  <th className="px-6 py-4 font-bold">Alert Signature</th>
                  <th className="px-6 py-4 font-bold">Source</th>
                  <th className="px-6 py-4 font-bold text-center">Threat</th>
                  <th className="px-6 py-4 font-bold text-right">Severity</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-900/50">
                {/* Handle disconnected state */}
                {!isConnected ? (
                  <tr>
                    <td colSpan={5} className="p-16 text-center">
                      <EmptyState 
                        icon={WifiOff}
                        title="Oracle Backend Offline"
                        description="Unable to connect to the Cardea Oracle backend. The system will automatically retry the connection. Check that the Oracle service is running."
                      />
                    </td>
                  </tr>
                ) : data?.alerts && data.alerts.length > 0 ? (
                  data.alerts.map((alert: Alert) => {
                    const config = severityConfig[alert.severity] || severityConfig.low;
                    const SeverityIcon = config.icon;
                    return (
                    <tr key={alert.id} className="hover:bg-slate-900/40 transition-colors group">
                      <td className="px-6 py-5 text-xs text-slate-500 font-mono tabular-nums">
                        {new Date(alert.timestamp).toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                      </td>
                      <td className="px-6 py-5">
                        <p className="text-sm font-semibold text-slate-300 group-hover:text-cyan-400 transition-colors">
                          {(alert.alert_type || 'Unknown').replaceAll('_', ' ').toUpperCase()}
                        </p>
                        <p className="text-xs text-slate-500 mt-0.5 line-clamp-1 italic max-w-md">"{alert.description}"</p>
                      </td>
                      <td className="px-6 py-5 text-xs font-mono text-slate-400">
                        {alert.source}
                      </td>
                      <td className="px-6 py-5 text-center">
                        {alert.threat_score !== undefined && alert.threat_score !== null ? (
                          <span className={`text-[10px] font-bold tabular-nums ${
                            alert.threat_score >= 0.7 ? 'text-red-500' : 
                            alert.threat_score >= 0.4 ? 'text-yellow-500' : 'text-green-500'
                          }`}>
                            {(alert.threat_score * 100).toFixed(0)}%
                          </span>
                        ) : (
                          <span className="text-[10px] text-slate-600">—</span>
                        )}
                      </td>
                      <td className="px-6 py-5 text-right">
                        <span className={`inline-flex items-center gap-1.5 text-[9px] font-black px-2.5 py-1 rounded border tracking-tighter ${config.bg} ${config.color}`}>
                          <SeverityIcon className="w-3 h-3" />
                          {alert.severity.toUpperCase()}
                        </span>
                      </td>
                    </tr>
                  )})
                ) : (
                  <tr>
                    <td colSpan={5} className="p-16 text-center">
                      <EmptyState 
                        icon={Shield}
                        title="No Active Threats"
                        description="No tactical anomalies detected in the current monitoring buffer. The network appears secure."
                      />
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