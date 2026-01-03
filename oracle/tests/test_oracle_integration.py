#!/usr/bin/env python3
"""
Oracle Backend Test Script
Comprehensive testing of Oracle backend functionality and Sentry integration
"""

import asyncio
import aiohttp
import json
import logging
from datetime import datetime, timezone
from typing import Dict, Any

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class OracleBackendTester:
    """Test Oracle backend functionality"""
    
    def __init__(self, oracle_url: str = "http://localhost:8000", webhook_token: str = "dev_webhook_token"):
        self.oracle_url = oracle_url.rstrip('/')
        self.webhook_token = webhook_token
        self.session = None
        self.headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {webhook_token}"
        }
    
    async def __aenter__(self):
        self.session = aiohttp.ClientSession(headers=self.headers)
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    async def test_health_check(self) -> bool:
        """Test Oracle health endpoint"""
        logger.info("🏥 Testing Oracle health check...")
        try:
            async with self.session.get(f"{self.oracle_url}/health") as response:
                if response.status == 200:
                    health_data = await response.json()
                    logger.info(f"✅ Oracle health: {health_data.get('status')}")
                    logger.info(f"   Version: {health_data.get('version')}")
                    logger.info(f"   Services: {list(health_data.get('services', {}).keys())}")
                    return True
                else:
                    logger.error(f"❌ Health check failed: {response.status}")
                    return False
        except Exception as e:
            logger.error(f"❌ Health check error: {e}")
            return False
    
    async def test_alert_submission(self) -> bool:
        """Test alert submission endpoint"""
        logger.info("📢 Testing alert submission...")
        
        test_alert = {
            "source": "test_sentry",
            "alert_type": "network_anomaly",
            "severity": "high", 
            "title": "Test Network Anomaly Alert",
            "description": "This is a test alert to verify Oracle backend functionality",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "raw_data": {
                "test_data": True,
                "anomaly_score": 0.85,
                "detection_method": "test"
            },
            "network_context": {
                "source_ip": "192.168.1.100",
                "dest_ip": "8.8.8.8",
                "source_port": 12345,
                "dest_port": 53,
                "protocol": "udp"
            },
            "indicators": ["192.168.1.100", "suspicious_dns_query"]
        }
        
        try:
            async with self.session.post(f"{self.oracle_url}/api/alerts", json=test_alert) as response:
                if response.status == 200:
                    result = await response.json()
                    logger.info(f"✅ Alert submitted successfully: ID {result.get('alert_id')}")
                    logger.info(f"   Status: {result.get('status')}")
                    logger.info(f"   Processing time: {result.get('processing_time_ms')}ms")
                    return True
                else:
                    error_text = await response.text()
                    logger.error(f"❌ Alert submission failed: {response.status} - {error_text}")
                    return False
        except Exception as e:
            logger.error(f"❌ Alert submission error: {e}")
            return False
    
    async def test_threat_analysis(self) -> bool:
        """Test threat analysis endpoint"""
        logger.info("🔍 Testing threat analysis...")
        
        analysis_request = {
            "time_window": 3600,  # Last hour
            "threat_types": ["network_anomaly", "intrusion_detection"],
            "severity_filter": "high",
            "include_correlations": True
        }
        
        try:
            async with self.session.post(f"{self.oracle_url}/api/threat-analysis", json=analysis_request) as response:
                if response.status == 200:
                    result = await response.json()
                    logger.info(f"✅ Threat analysis completed: ID {result.get('analysis_id')}")
                    logger.info(f"   Threats detected: {len(result.get('threats_detected', []))}")
                    logger.info(f"   Risk score: {result.get('risk_score', 0):.3f}")
                    logger.info(f"   Recommendations: {len(result.get('recommendations', []))}")
                    return True
                else:
                    error_text = await response.text()
                    logger.error(f"❌ Threat analysis failed: {response.status} - {error_text}")
                    return False
        except Exception as e:
            logger.error(f"❌ Threat analysis error: {e}")
            return False
    
    async def test_analytics(self) -> bool:
        """Test analytics endpoint"""
        logger.info("📊 Testing analytics...")
        
        try:
            async with self.session.get(f"{self.oracle_url}/api/analytics?time_range=24h") as response:
                if response.status == 200:
                    result = await response.json()
                    logger.info(f"✅ Analytics retrieved successfully")
                    logger.info(f"   Total alerts: {result.get('total_alerts', 0)}")
                    logger.info(f"   Time range: {result.get('time_range')}")
                    logger.info(f"   Top threats: {len(result.get('top_threats', []))}")
                    return True
                else:
                    error_text = await response.text()
                    logger.error(f"❌ Analytics failed: {response.status} - {error_text}")
                    return False
        except Exception as e:
            logger.error(f"❌ Analytics error: {e}")
            return False
    
    async def test_sentry_integration(self) -> bool:
        """Test various Sentry alert formats"""
        logger.info("🔗 Testing Sentry integration scenarios...")
        
        # Test KitNET anomaly alert
        kitnet_alert = {
            "source": "kitnet",
            "alert_type": "network_anomaly",
            "severity": "critical",
            "title": "KitNET Anomaly Detection",
            "description": "High anomaly score detected by KitNET AI",
            "raw_data": {
                "anomaly_score": 0.95,
                "feature_vector": [0.1, 0.2, 0.8, 0.9],
                "detection_timestamp": datetime.now().isoformat()
            },
            "network_context": {
                "source_ip": "10.0.1.45",
                "dest_ip": "203.0.113.5",
                "bytes_transferred": 1500000
            },
            "indicators": ["10.0.1.45", "suspicious_traffic_volume"]
        }
        
        # Test Suricata IDS alert
        suricata_alert = {
            "source": "suricata",
            "alert_type": "intrusion_detection", 
            "severity": "high",
            "title": "Suricata IDS Alert",
            "description": "Potential intrusion attempt detected",
            "raw_data": {
                "signature": "ET MALWARE Suspicious DNS Query",
                "signature_id": 2024001,
                "category": "trojan-activity",
                "classification": 1
            },
            "network_context": {
                "source_ip": "192.168.1.200",
                "dest_ip": "8.8.8.8",
                "source_port": 5678,
                "dest_port": 53,
                "protocol": "udp"
            },
            "indicators": ["192.168.1.200", "malicious_dns_query"]
        }
        
        # Test Zeek analysis alert
        zeek_alert = {
            "source": "zeek",
            "alert_type": "suspicious_behavior",
            "severity": "medium",
            "title": "Zeek Network Analysis",
            "description": "Suspicious network behavior detected",
            "raw_data": {
                "conn_state": "SF",
                "orig_bytes": 1024,
                "resp_bytes": 2048,
                "service": "http",
                "duration": 30.5
            },
            "network_context": {
                "source_ip": "192.168.1.150",
                "dest_ip": "198.51.100.10",
                "source_port": 8080,
                "dest_port": 80,
                "protocol": "tcp"
            },
            "indicators": ["192.168.1.150", "unusual_http_behavior"]
        }
        
        success_count = 0
        test_alerts = [
            ("KitNET", kitnet_alert),
            ("Suricata", suricata_alert), 
            ("Zeek", zeek_alert)
        ]
        
        for service_name, alert in test_alerts:
            try:
                async with self.session.post(f"{self.oracle_url}/api/alerts", json=alert) as response:
                    if response.status == 200:
                        result = await response.json()
                        logger.info(f"✅ {service_name} alert processed: ID {result.get('alert_id')}")
                        success_count += 1
                    else:
                        error_text = await response.text()
                        logger.error(f"❌ {service_name} alert failed: {response.status}")
            except Exception as e:
                logger.error(f"❌ {service_name} alert error: {e}")
        
        logger.info(f"Sentry integration test: {success_count}/{len(test_alerts)} successful")
        return success_count == len(test_alerts)
    
    async def run_comprehensive_test(self):
        """Run all Oracle backend tests"""
        logger.info("🚀 Starting comprehensive Oracle backend test...")
        
        tests = [
            ("Health Check", self.test_health_check),
            ("Alert Submission", self.test_alert_submission),
            ("Threat Analysis", self.test_threat_analysis),
            ("Analytics", self.test_analytics),
            ("Sentry Integration", self.test_sentry_integration)
        ]
        
        results = {}
        
        for test_name, test_func in tests:
            logger.info(f"\n--- Running {test_name} ---")
            try:
                results[test_name] = await test_func()
            except Exception as e:
                logger.error(f"❌ {test_name} failed with exception: {e}")
                results[test_name] = False
        
        # Summary
        logger.info("\n" + "="*50)
        logger.info("TEST SUMMARY")
        logger.info("="*50)
        
        passed = sum(results.values())
        total = len(results)
        
        for test_name, result in results.items():
            status = "✅ PASS" if result else "❌ FAIL"
            logger.info(f"{test_name:<20} {status}")
        
        logger.info(f"\nOverall: {passed}/{total} tests passed")
        
        if passed == total:
            logger.info("🎉 All tests passed! Oracle backend is ready for deployment.")
        else:
            logger.warning(f"⚠️ {total - passed} tests failed. Please review the issues above.")
        
        return results

async def main():
    """Main test execution"""
    oracle_url = "http://localhost:8000"
    
    logger.info(f"Testing Oracle backend at: {oracle_url}")
    
    async with OracleBackendTester(oracle_url) as tester:
        results = await tester.run_comprehensive_test()
        
        # Return exit code based on test results
        return 0 if all(results.values()) else 1

if __name__ == "__main__":
    exit_code = asyncio.run(main())