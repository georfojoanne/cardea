-- Oracle Backend Database Initialization Script
-- Create additional database objects and initial data

-- Create indexes for better query performance
CREATE INDEX IF NOT EXISTS idx_alerts_timestamp_desc ON alerts (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_threat_score_desc ON alerts (threat_score DESC);
CREATE INDEX IF NOT EXISTS idx_threat_intel_updated ON threat_intelligence (updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_system_metrics_timestamp ON system_metrics (timestamp DESC);

-- Create partitions for better performance (optional, for large datasets)
-- This can be enabled later as data grows

-- Insert default threat intelligence data
INSERT INTO threat_intelligence (
    threat_id, threat_type, severity, confidence_score,
    name, description, indicators, first_seen, last_seen
) VALUES 
    ('default_malware_001', 'malware_detection', 'high', 0.9,
     'Generic Malware Pattern', 'Default malware detection pattern',
     '["suspicious_executable", "malicious_registry_key"]'::json,
     NOW(), NOW()
    ),
    ('default_intrusion_001', 'intrusion_detection', 'high', 0.85,
     'Network Intrusion Pattern', 'Default network intrusion pattern',
     '["unauthorized_access", "suspicious_network_activity"]'::json,
     NOW(), NOW()
    )
ON CONFLICT (threat_id) DO NOTHING;

-- Create a view for alert analytics
CREATE OR REPLACE VIEW alert_analytics AS
SELECT 
    DATE_TRUNC('hour', timestamp) as hour,
    alert_type,
    severity,
    COUNT(*) as alert_count,
    AVG(threat_score) as avg_threat_score,
    MAX(threat_score) as max_threat_score
FROM alerts
WHERE timestamp >= NOW() - INTERVAL '7 days'
GROUP BY DATE_TRUNC('hour', timestamp), alert_type, severity
ORDER BY hour DESC;

-- Create a view for threat summary
CREATE OR REPLACE VIEW threat_summary AS
SELECT 
    threat_type,
    severity,
    COUNT(*) as total_count,
    AVG(confidence_score) as avg_confidence,
    MAX(updated_at) as last_updated
FROM threat_intelligence
GROUP BY threat_type, severity;

-- Function to cleanup old alerts (for maintenance)
CREATE OR REPLACE FUNCTION cleanup_old_alerts(retention_days INTEGER DEFAULT 90)
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    DELETE FROM alerts 
    WHERE timestamp < NOW() - (retention_days || ' days')::INTERVAL;
    
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    
    -- Log the cleanup
    INSERT INTO system_metrics (metric_name, metric_value, timestamp)
    VALUES ('alerts_cleaned_up', deleted_count, NOW());
    
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- Function to calculate threat score statistics
CREATE OR REPLACE FUNCTION get_threat_stats()
RETURNS TABLE (
    total_alerts INTEGER,
    high_threat_alerts INTEGER,
    avg_threat_score NUMERIC,
    latest_threat_timestamp TIMESTAMP
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        COUNT(*)::INTEGER as total_alerts,
        COUNT(CASE WHEN threat_score > 0.7 THEN 1 END)::INTEGER as high_threat_alerts,
        ROUND(AVG(threat_score), 3) as avg_threat_score,
        MAX(timestamp) as latest_threat_timestamp
    FROM alerts
    WHERE timestamp >= NOW() - INTERVAL '24 hours';
END;
$$ LANGUAGE plpgsql;

-- Initial system metrics
INSERT INTO system_metrics (metric_name, metric_value, metric_unit, timestamp) VALUES
    ('system_initialized', 1, 'boolean', NOW()),
    ('database_version', 1.0, 'version', NOW());

COMMIT;