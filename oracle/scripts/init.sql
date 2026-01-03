-- Oracle Backend Database Initialization Script
-- Basic database setup for development

-- Create a basic test to ensure database is working
SELECT 1 as database_ready;

-- Note: Tables will be created by SQLAlchemy when the application starts
-- This script is just for basic database validation

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