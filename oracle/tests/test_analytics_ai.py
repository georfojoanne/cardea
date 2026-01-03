"""
Test AI-Powered Agentic Analytics
Validation tests for upgraded ThreatAnalyzer
"""

import pytest
import asyncio
from datetime import datetime, timezone
from unittest.mock import Mock, AsyncMock, patch

from analytics import ThreatAnalyzer, AlertCorrelator
from models import AlertType, AlertSeverity
from database import Alert


class TestAgenticThreatAnalyzer:
    """Test suite for AI-powered ThreatAnalyzer"""
    
    @pytest.fixture
    def analyzer(self):
        """Create ThreatAnalyzer instance"""
        return ThreatAnalyzer()
    
    @pytest.fixture
    def sample_alert(self):
        """Create sample alert for testing"""
        alert = Mock(spec=Alert)
        alert.id = 1
        alert.source = "bridge"
        alert.alert_type = AlertType.DATA_EXFILTRATION.value
        alert.severity = AlertSeverity.HIGH.value
        alert.title = "Unusual data transfer detected"
        alert.description = "Large outbound transfer at 2:00 AM"
        alert.timestamp = datetime.now(timezone.utc)
        alert.network_context = {
            "source_ip": "192.168.1.100",
            "dest_ip": "45.33.32.156",
            "bytes_transferred": 5000000,
            "dest_port": 443,
            "external_connection": True
        }
        alert.raw_data = {
            "bytes_transferred": 5000000,
            "connection_count": 150
        }
        alert.indicators = ["45.33.32.156", "port:443"]
        return alert
    
    def test_analyzer_initialization(self, analyzer):
        """Test ThreatAnalyzer initializes correctly"""
        assert analyzer is not None
        assert analyzer.severity_weights is not None
        assert analyzer.alert_type_weights is not None
        assert hasattr(analyzer, 'ai_client')
    
    @pytest.mark.asyncio
    async def test_deterministic_scoring_fallback(self, analyzer, sample_alert):
        """Test deterministic scoring works without AI"""
        # Ensure AI client is None for fallback test
        analyzer.ai_client = None
        
        score = await analyzer.calculate_threat_score(sample_alert)
        
        assert 0.0 <= score <= 1.0, "Score should be between 0 and 1"
        assert score > 0.5, "High severity data exfiltration should score high"
    
    @pytest.mark.asyncio
    async def test_context_scoring(self, analyzer, sample_alert):
        """Test context-based scoring component"""
        score = await analyzer._calculate_context_score(sample_alert)
        
        assert 0.0 <= score <= 1.0
        # Should score high due to external connection, large transfer, high connection count
        assert score >= 0.5, "Context should indicate suspicious activity"
    
    @pytest.mark.asyncio
    @patch('analytics.AsyncAzureOpenAI')
    async def test_ai_scoring_with_mock(self, mock_openai_class, analyzer, sample_alert):
        """Test AI-powered scoring with mocked OpenAI response"""
        # Mock OpenAI response
        mock_client = AsyncMock()
        mock_response = Mock()
        mock_response.choices = [Mock()]
        mock_response.choices[0].message.content = """```json
{
  "kill_chain_stage": "Actions on Objectives",
  "threat_score": 0.88,
  "intent": "Data exfiltration - stealing sensitive information",
  "confidence": 0.92,
  "reasoning": "Large data transfer to external IP at unusual time"
}
```"""
        mock_response.usage.total_tokens = 456
        
        mock_client.chat.completions.create = AsyncMock(return_value=mock_response)
        analyzer.ai_client = mock_client
        
        score = await analyzer._calculate_threat_score_ai(sample_alert)
        
        assert 0.0 <= score <= 1.0
        # Score should be threat_score * confidence = 0.88 * 0.92 ≈ 0.81
        assert 0.75 <= score <= 0.95
        assert mock_client.chat.completions.create.called
    
    @pytest.mark.asyncio
    async def test_reason_with_ai_fallback(self, analyzer):
        """Test AI reasoning returns None when client unavailable"""
        analyzer.ai_client = None
        
        response = await analyzer.reason_with_ai(
            prompt="Test prompt",
            context={"test": "data"}
        )
        
        assert response is None
    
    @pytest.mark.asyncio
    async def test_deterministic_recommendations(self, analyzer):
        """Test deterministic recommendations generation"""
        from models import ThreatInfo
        
        threats = [
            ThreatInfo(
                threat_id="threat_1",
                threat_type=AlertType.MALWARE_DETECTION,
                severity=AlertSeverity.CRITICAL,
                confidence_score=0.95,
                first_seen=datetime.now(timezone.utc),
                last_seen=datetime.now(timezone.utc),
                indicators=["malicious.exe"],
                affected_assets=["host_1"]
            ),
            ThreatInfo(
                threat_id="threat_2",
                threat_type=AlertType.DATA_EXFILTRATION,
                severity=AlertSeverity.HIGH,
                confidence_score=0.88,
                first_seen=datetime.now(timezone.utc),
                last_seen=datetime.now(timezone.utc),
                indicators=["45.33.32.156"],
                affected_assets=["host_2"]
            )
        ]
        
        recommendations = analyzer._generate_recommendations_deterministic(threats)
        
        assert len(recommendations) > 0
        assert any("malware" in rec.lower() for rec in recommendations)
        assert any("exfiltration" in rec.lower() or "data" in rec.lower() for rec in recommendations)
    
    @pytest.mark.asyncio
    async def test_threshold_recommendation_deterministic(self, analyzer):
        """Test deterministic threshold recommendation"""
        # Mock alerts with high severity ratio
        alerts = []
        for i in range(10):
            alert = Mock(spec=Alert)
            alert.severity = AlertSeverity.HIGH.value if i < 8 else AlertSeverity.LOW.value
            alerts.append(alert)
        
        recommendation = analyzer._recommend_threshold_deterministic(
            alerts=alerts,
            threats=[],
            time_window=3600
        )
        
        assert recommendation is not None
        assert "action" in recommendation
        assert recommendation["action"] in ["LOWER", "MAINTAIN", "RAISE"]
        assert "recommended_value" in recommendation
        assert 0.90 <= recommendation["recommended_value"] <= 0.98
    
    def test_attack_pattern_matching(self, analyzer):
        """Test suspicious pattern detection"""
        assert analyzer._matches_attack_pattern("malware.exe")
        assert analyzer._matches_attack_pattern("shell.php?cmd=whoami")
        assert analyzer._matches_attack_pattern("<script>alert(1)</script>")
        assert not analyzer._matches_attack_pattern("normal_file.txt")


class TestAlertCorrelator:
    """Test suite for AlertCorrelator"""
    
    @pytest.fixture
    def correlator(self):
        return AlertCorrelator()
    
    def test_correlator_initialization(self, correlator):
        """Test AlertCorrelator initializes correctly"""
        assert correlator is not None
        assert len(correlator.correlation_algorithms) == 3
        assert "temporal" in correlator.correlation_algorithms
        assert "network" in correlator.correlation_algorithms
        assert "behavioral" in correlator.correlation_algorithms


def test_import_statements():
    """Test all required imports are available"""
    try:
        from analytics import ThreatAnalyzer, AlertCorrelator
        from models import AlertType, AlertSeverity, ThreatInfo
        from database import Alert
        from config import settings
        assert True
    except ImportError as e:
        pytest.fail(f"Import failed: {e}")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
