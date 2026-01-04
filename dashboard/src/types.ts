export interface Alert {
    id: number;
    source: string;
    alert_type: string;
    severity: 'low' | 'medium' | 'high' | 'critical';
    title: string;
    description: string;
    timestamp: string;
    threat_score?: number;
    raw_data?: Record<string, any>;
  }
  
  export interface AnalyticsResponse {
    total_alerts: number;
    risk_score: number;
    alerts: Alert[];
  }

  export interface FlowData {
    nodes: Array<{
      id: string;
      type: string;
      data: { label: string; status?: string };
      position: { x: number; y: number };
    }>;
    edges: Array<{
      id: string;
      source: string;
      target: string;
      animated?: boolean;
    }>;
  }