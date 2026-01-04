import asyncio
import httpx
import json

async def test_oracle_ingestion():
    # Use localhost if running via docker-compose with ports mapped
    url = "http://localhost:8000/api/alerts"
    
    payload = {
        "source": "manual_smoke_test",
        "alert_type": "network_anomaly",
        "severity": "high",
        "title": "Smoke Test Alert",
        "description": "Testing the Async Postgres + Azure OpenAI pipeline",
        "raw_data": {"test_metric": 0.99},
        "timestamp": "2026-01-03T21:00:00Z"
    }
    
    async with httpx.AsyncClient() as client:
        print("🚀 Sending test alert to Oracle...")
        try:
            # Note: If you still have Auth enabled, add headers here
            response = await client.post(url, json=payload, timeout=15.0)
            print(f"📡 Status Code: {response.status_code}")
            print(f"📦 Response: {json.dumps(response.json(), indent=2)}")
        except Exception as e:
            print(f"❌ Connection Failed: {e}")

if __name__ == "__main__":
    asyncio.run(test_oracle_ingestion())