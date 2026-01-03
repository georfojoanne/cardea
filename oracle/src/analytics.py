"""
Analytics and Threat Processing
Advanced threat analysis and alert correlation algorithms
"""

import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Optional, Tuple
import numpy as np
from collections import defaultdict, Counter
import json

from models import AlertType, AlertSeverity, ThreatInfo
from database import get_db, Alert, ThreatIntelligence, AlertCorrelation

logger = logging.getLogger(__name__)

class ThreatAnalyzer:
    """Advanced threat analysis and scoring"""
    
    def __init__(self):
        self.threat_patterns = self._load_threat_patterns()
        self.severity_weights = {
            AlertSeverity.LOW: 0.2,
            AlertSeverity.MEDIUM: 0.5,
            AlertSeverity.HIGH: 0.8,
            AlertSeverity.CRITICAL: 1.0
        }
        self.alert_type_weights = {
            AlertType.NETWORK_ANOMALY: 0.6,
            AlertType.INTRUSION_DETECTION: 0.9,
            AlertType.MALWARE_DETECTION: 1.0,
            AlertType.SUSPICIOUS_BEHAVIOR: 0.7,
            AlertType.DATA_EXFILTRATION: 1.0,
            AlertType.UNAUTHORIZED_ACCESS: 0.9
        }
    
    def _load_threat_patterns(self) -> Dict[str, Any]:
        """Load threat intelligence patterns"""
        # In production, this would load from threat intelligence feeds
        return {
            "malicious_ips": set(),
            "suspicious_domains": set(),
            "attack_signatures": [],
            "behavioral_patterns": {}
        }
    
    async def calculate_threat_score(self, alert: Alert) -> float:
        """Calculate comprehensive threat score for an alert"""
        try:
            base_score = 0.0
            
            # Base score from severity and type
            severity_score = self.severity_weights.get(AlertSeverity(alert.severity), 0.5)
            type_score = self.alert_type_weights.get(AlertType(alert.alert_type), 0.5)
            base_score = (severity_score + type_score) / 2
            
            # Contextual scoring
            context_score = await self._calculate_context_score(alert)
            
            # Historical scoring (based on similar alerts)
            historical_score = await self._calculate_historical_score(alert)
            
            # Indicator scoring (based on threat intelligence)
            indicator_score = await self._calculate_indicator_score(alert)
            
            # Combine scores with weights
            final_score = (
                base_score * 0.3 +
                context_score * 0.3 +
                historical_score * 0.2 +
                indicator_score * 0.2
            )
            
            # Normalize to 0-1 range
            final_score = max(0.0, min(1.0, final_score))
            
            logger.info(f"Calculated threat score {final_score:.3f} for alert {alert.id}")
            return final_score
            
        except Exception as e:
            logger.error(f"Threat score calculation failed for alert {alert.id}: {e}")
            return 0.5  # Default moderate score
    
    async def _calculate_context_score(self, alert: Alert) -> float:
        """Calculate score based on alert context"""
        score = 0.0
        
        try:
            if alert.network_context:
                # Check for suspicious network patterns
                network_data = alert.network_context
                
                # High frequency of connections
                if network_data.get("connection_count", 0) > 100:
                    score += 0.3
                
                # Unusual ports
                unusual_ports = {22, 23, 135, 139, 445, 1433, 3389}
                if network_data.get("dest_port") in unusual_ports:
                    score += 0.2
                
                # External connections
                if network_data.get("external_connection", False):
                    score += 0.2
            
            # Check raw data for additional indicators
            if alert.raw_data:
                raw = alert.raw_data
                
                # Large data transfers
                if raw.get("bytes_transferred", 0) > 1000000:  # > 1MB
                    score += 0.2
                
                # Failed authentication attempts
                if "failed_auth" in raw and raw["failed_auth"] > 5:
                    score += 0.3
        
        except Exception as e:
            logger.warning(f"Context scoring failed for alert {alert.id}: {e}")
        
        return min(1.0, score)
    
    async def _calculate_historical_score(self, alert: Alert) -> float:
        """Calculate score based on historical alert patterns"""
        try:
            async with get_db() as db:
                # Look for similar alerts in the last 24 hours
                time_threshold = datetime.now(timezone.utc) - timedelta(hours=24)
                
                similar_alerts = await db.execute(
                    "SELECT COUNT(*) FROM alerts WHERE alert_type = %s AND timestamp > %s",
                    (alert.alert_type, time_threshold)
                )
                count = similar_alerts.scalar() or 0
                
                # Higher frequency = higher score
                if count > 10:
                    return 0.8
                elif count > 5:
                    return 0.6
                elif count > 2:
                    return 0.4
                else:
                    return 0.2
                    
        except Exception as e:
            logger.warning(f"Historical scoring failed for alert {alert.id}: {e}")
            return 0.3
    
    async def _calculate_indicator_score(self, alert: Alert) -> float:
        """Calculate score based on threat intelligence indicators"""
        score = 0.0
        
        try:
            if alert.indicators:
                for indicator in alert.indicators:
                    # Check against known threat indicators
                    if indicator in self.threat_patterns["malicious_ips"]:
                        score += 0.4
                    elif indicator in self.threat_patterns["suspicious_domains"]:
                        score += 0.3
                    
                    # Pattern matching for suspicious indicators
                    if self._matches_attack_pattern(indicator):
                        score += 0.2
        
        except Exception as e:
            logger.warning(f"Indicator scoring failed for alert {alert.id}: {e}")
        
        return min(1.0, score)
    
    def _matches_attack_pattern(self, indicator: str) -> bool:
        """Check if indicator matches known attack patterns"""
        # Simplified pattern matching - would be more sophisticated in production
        suspicious_patterns = [
            r'.*\.exe$',  # Executable files
            r'.*\.(php|jsp|asp).*\?.*',  # Web shell patterns
            r'.*[\<\>].*',  # Script injection attempts
        ]
        
        import re
        for pattern in suspicious_patterns:
            if re.match(pattern, indicator, re.IGNORECASE):
                return True
        return False
    
    async def analyze_threats(
        self,
        time_window: int,
        threat_types: List[AlertType] = None,
        severity_filter: AlertSeverity = None
    ) -> Dict[str, Any]:
        """Comprehensive threat analysis across time window"""
        
        try:
            end_time = datetime.now(timezone.utc)
            start_time = end_time - timedelta(seconds=time_window)
            
            async with get_db() as db:
                # Build query filters
                filters = ["timestamp >= %s AND timestamp <= %s"]
                params = [start_time, end_time]
                
                if threat_types:
                    filters.append(f"alert_type IN ({','.join(['%s'] * len(threat_types))})")
                    params.extend([t.value for t in threat_types])
                
                if severity_filter:
                    filters.append("severity = %s")
                    params.append(severity_filter.value)
                
                # Get alerts for analysis
                query = f"SELECT * FROM alerts WHERE {' AND '.join(filters)}"
                result = await db.execute(query, params)
                alerts = result.fetchall()
                
                # Analyze threats
                threats_detected = []
                correlations = []
                
                # Group alerts by patterns
                threat_groups = self._group_threats(alerts)
                
                for group_id, group_alerts in threat_groups.items():
                    threat_info = await self._analyze_threat_group(group_alerts)
                    if threat_info:
                        threats_detected.append(threat_info)
                
                # Calculate overall risk score
                risk_score = self._calculate_overall_risk(threats_detected)
                
                # Generate recommendations
                recommendations = self._generate_recommendations(threats_detected)
                
                return {
                    "threats": threats_detected,
                    "risk_score": risk_score,
                    "recommendations": recommendations,
                    "correlations": correlations
                }
                
        except Exception as e:
            logger.error(f"Threat analysis failed: {e}")
            return {
                "threats": [],
                "risk_score": 0.0,
                "recommendations": [],
                "correlations": []
            }
    
    def _group_threats(self, alerts: List[Alert]) -> Dict[str, List[Alert]]:
        """Group related alerts into threat clusters"""
        groups = defaultdict(list)
        
        for alert in alerts:
            # Simple grouping by alert type and source
            group_key = f"{alert.alert_type}_{alert.source}"
            groups[group_key].append(alert)
        
        return groups
    
    async def _analyze_threat_group(self, alerts: List[Alert]) -> Optional[ThreatInfo]:
        """Analyze a group of related alerts"""
        if not alerts:
            return None
        
        try:
            # Calculate group statistics
            severities = [a.severity for a in alerts]
            most_severe = max(severities, key=lambda s: self.severity_weights.get(AlertSeverity(s), 0))
            
            # Aggregate indicators
            all_indicators = []
            for alert in alerts:
                if alert.indicators:
                    all_indicators.extend(alert.indicators)
            
            # Calculate confidence based on alert count and consistency
            confidence_score = min(1.0, len(alerts) * 0.1 + 0.3)
            
            return ThreatInfo(
                threat_id=f"threat_{alerts[0].alert_type}_{int(datetime.now().timestamp())}",
                threat_type=AlertType(alerts[0].alert_type),
                severity=AlertSeverity(most_severe),
                confidence_score=confidence_score,
                first_seen=min(a.timestamp for a in alerts),
                last_seen=max(a.timestamp for a in alerts),
                indicators=list(set(all_indicators)),
                affected_assets=[f"{a.source}_{a.id}" for a in alerts]
            )
            
        except Exception as e:
            logger.error(f"Threat group analysis failed: {e}")
            return None
    
    def _calculate_overall_risk(self, threats: List[ThreatInfo]) -> float:
        """Calculate overall risk score from detected threats"""
        if not threats:
            return 0.0
        
        # Weight threats by severity and confidence
        total_risk = 0.0
        for threat in threats:
            severity_weight = self.severity_weights.get(threat.severity, 0.5)
            risk_contribution = severity_weight * threat.confidence_score
            total_risk += risk_contribution
        
        # Normalize by number of threats with diminishing returns
        risk_score = total_risk / (1 + len(threats) * 0.1)
        return min(1.0, risk_score)
    
    def _generate_recommendations(self, threats: List[ThreatInfo]) -> List[str]:
        """Generate security recommendations based on detected threats"""
        recommendations = []
        
        threat_types = [t.threat_type for t in threats]
        
        if AlertType.MALWARE_DETECTION in threat_types:
            recommendations.append("Perform full system malware scan and isolate affected systems")
        
        if AlertType.INTRUSION_DETECTION in threat_types:
            recommendations.append("Review firewall rules and network access controls")
        
        if AlertType.DATA_EXFILTRATION in threat_types:
            recommendations.append("Investigate data access logs and implement DLP controls")
        
        if AlertType.UNAUTHORIZED_ACCESS in threat_types:
            recommendations.append("Review user access permissions and authentication logs")
        
        # General recommendations
        if len(threats) > 5:
            recommendations.append("Consider raising security alert level due to high threat volume")
        
        high_severity_count = sum(1 for t in threats if t.severity in [AlertSeverity.HIGH, AlertSeverity.CRITICAL])
        if high_severity_count > 2:
            recommendations.append("Immediate security team escalation recommended")
        
        return recommendations

class AlertCorrelator:
    """Alert correlation and relationship detection"""
    
    def __init__(self):
        self.correlation_algorithms = {
            "temporal": self._temporal_correlation,
            "network": self._network_correlation,
            "behavioral": self._behavioral_correlation
        }
    
    async def find_correlations(self, alert: Alert) -> List[Dict[str, Any]]:
        """Find correlations for a given alert"""
        correlations = []
        
        try:
            for correlation_type, algorithm in self.correlation_algorithms.items():
                related_alerts = await algorithm(alert)
                for related_alert, score in related_alerts:
                    correlations.append({
                        "type": correlation_type,
                        "related_alert_id": related_alert.id,
                        "correlation_score": score,
                        "reason": f"{correlation_type} correlation detected"
                    })
        
        except Exception as e:
            logger.error(f"Correlation analysis failed for alert {alert.id}: {e}")
        
        return correlations
    
    async def _temporal_correlation(self, alert: Alert) -> List[Tuple[Alert, float]]:
        """Find temporally correlated alerts"""
        correlations = []
        
        try:
            # Look for alerts within ±30 minutes
            time_window = timedelta(minutes=30)
            start_time = alert.timestamp - time_window
            end_time = alert.timestamp + time_window
            
            async with get_db() as db:
                result = await db.execute(
                    "SELECT * FROM alerts WHERE timestamp BETWEEN %s AND %s AND id != %s",
                    (start_time, end_time, alert.id)
                )
                nearby_alerts = result.fetchall()
                
                for nearby_alert in nearby_alerts:
                    # Calculate temporal correlation score
                    time_diff = abs((alert.timestamp - nearby_alert.timestamp).total_seconds())
                    score = max(0.0, 1.0 - (time_diff / 1800))  # 30 minutes = 0 score
                    
                    if score > 0.5:  # Threshold for correlation
                        correlations.append((nearby_alert, score))
        
        except Exception as e:
            logger.warning(f"Temporal correlation failed: {e}")
        
        return correlations
    
    async def _network_correlation(self, alert: Alert) -> List[Tuple[Alert, float]]:
        """Find network-based correlations"""
        correlations = []
        
        try:
            if not alert.network_context:
                return correlations
            
            source_ip = alert.network_context.get("source_ip")
            dest_ip = alert.network_context.get("dest_ip")
            
            if source_ip or dest_ip:
                async with get_db() as db:
                    # Find alerts with same IP addresses
                    result = await db.execute(
                        """
                        SELECT * FROM alerts 
                        WHERE id != %s AND (
                            network_context->>'source_ip' = %s OR
                            network_context->>'dest_ip' = %s OR
                            network_context->>'source_ip' = %s OR
                            network_context->>'dest_ip' = %s
                        )
                        """,
                        (alert.id, source_ip, dest_ip, dest_ip, source_ip)
                    )
                    related_alerts = result.fetchall()
                    
                    for related_alert in related_alerts:
                        # Calculate network correlation score
                        score = 0.8  # High score for IP matches
                        correlations.append((related_alert, score))
        
        except Exception as e:
            logger.warning(f"Network correlation failed: {e}")
        
        return correlations
    
    async def _behavioral_correlation(self, alert: Alert) -> List[Tuple[Alert, float]]:
        """Find behavioral pattern correlations"""
        correlations = []
        
        try:
            # Look for similar alert types from same source
            async with get_db() as db:
                result = await db.execute(
                    "SELECT * FROM alerts WHERE alert_type = %s AND source = %s AND id != %s",
                    (alert.alert_type, alert.source, alert.id)
                )
                similar_alerts = result.fetchall()
                
                for similar_alert in similar_alerts:
                    # Calculate behavioral correlation score based on similarity
                    score = 0.6  # Moderate score for same type/source
                    
                    # Increase score if similar severity
                    if similar_alert.severity == alert.severity:
                        score += 0.2
                    
                    correlations.append((similar_alert, score))
        
        except Exception as e:
            logger.warning(f"Behavioral correlation failed: {e}")
        
        return correlations