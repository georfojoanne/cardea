# AI-Powered Agentic Analytics

## Overview

The Oracle backend has been upgraded with **AI-powered agentic reasoning** using Azure OpenAI (GPT-4o). This transforms the threat analysis from deterministic rule-based scoring to intelligent, context-aware threat assessment.

## What Changed

### 1. **Agentic Threat Scoring** (`calculate_threat_score`)

**Before (Deterministic):**
- Fixed weight formulas combining severity, type, context, historical, and indicator scores
- No understanding of attack intent or context

**After (AI-Powered):**
```python
await threat_analyzer.calculate_threat_score(alert)
```
- AI analyzes the full context of each alert
- Identifies **Cyber Kill Chain stage** (Reconnaissance → Exfiltration)
- Provides **intent analysis**: What is the attacker trying to do?
- Confidence-weighted scoring based on evidence quality
- Automatic fallback to deterministic scoring if AI unavailable

**Example AI Analysis:**
```json
{
  "kill_chain_stage": "Command & Control",
  "threat_score": 0.87,
  "intent": "Establishing persistent backdoor access for data exfiltration",
  "confidence": 0.92,
  "reasoning": "Unusual outbound connections on port 443 with encrypted traffic patterns matching C2 beaconing"
}
```

### 2. **Human-Readable Recommendations** (`_generate_recommendations_ai`)

**Before:**
- Generic bullet points: "Review firewall rules"
- Technical jargon

**After:**
AI generates structured recommendations in **three sections for business owners**:

#### 📋 What Happened
Plain language explanation of the security event

#### ⚠️ Why It Matters  
Business impact and risk explanation

#### ✅ What To Do Now
Prioritized action items starting with action verbs

**Example:**
```
📋 WHAT HAPPENED: We detected unusual network activity at 2:00 AM from your point-of-sale system trying to send encrypted data to an unknown external server.

⚠️ WHY IT MATTERS: This pattern matches ransomware preparing to steal customer payment data. If not stopped, you could face data breach penalties and customer trust damage.

✅ WHAT TO DO NOW:
1. Disconnect the POS system from the network immediately
2. Contact your POS vendor to verify if legitimate update activity
3. Review transaction logs for the past 48 hours
4. Change all POS system passwords
5. Call your cyber insurance provider
```

### 3. **Adaptive Threshold Recommendations** (`_recommend_threshold_adjustment`)

**New Feature:**
AI analyzes alert patterns and recommends whether the **KITNET_THRESHOLD** on Sentry should be adjusted:

- **LOWER (0.90-0.94)**: More sensitive - if missing threats
- **MAINTAIN (0.95)**: Current setting is optimal
- **RAISE (0.96-0.98)**: Less sensitive - reduce false positives

**Example Recommendation:**
```json
{
  "action": "LOWER",
  "recommended_value": 0.93,
  "current_value": 0.95,
  "reasoning": "Low alert volume (2/hour) but 80% are high severity, suggesting system may be missing early-stage reconnaissance activities",
  "confidence": 0.85,
  "expected_impact": "Alert volume may increase by 20-30% but will catch more sophisticated attacks in earlier stages",
  "ai_generated": true
}
```

## Configuration

### Required Environment Variables

```bash
# Azure OpenAI Configuration
AZURE_OPENAI_API_KEY=your-api-key
AZURE_OPENAI_ENDPOINT=https://your-resource.openai.azure.com/
AZURE_OPENAI_DEPLOYMENT=gpt-4o
AZURE_OPENAI_API_VERSION=2024-08-01-preview

# AI Agent Settings
AI_ENABLED=true
AI_MODEL_TEMPERATURE=0.3  # Lower = more focused, Higher = more creative
AI_MAX_TOKENS=1500        # Balance between detail and cost
```

### Setup Steps

1. **Create Azure OpenAI Resource**:
   - Go to [Azure Portal](https://portal.azure.com)
   - Create "Azure OpenAI" service
   - Deploy GPT-4o model (or gpt-4o-mini for cost efficiency)

2. **Get Credentials**:
   - Navigate to your Azure OpenAI resource
   - Copy API Key from "Keys and Endpoint"
   - Copy Endpoint URL
   - Note your deployment name

3. **Configure Oracle**:
   ```bash
   cd oracle
   cp .env.example .env
   # Edit .env with your Azure credentials
   ```

4. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

## Cost Optimization

### Token Usage Per Analysis

- **Threat Scoring**: ~300-500 tokens per alert
- **Recommendations**: ~800-1200 tokens per analysis
- **Threshold Adjustment**: ~400-600 tokens

### Recommended Model Tiers

1. **Development**: `gpt-4o-mini` (~$0.15 per 1M tokens)
2. **Production**: `gpt-4o` (~$5 per 1M tokens) - Better reasoning
3. **High Volume**: `gpt-35-turbo` (~$0.50 per 1M tokens) - Acceptable quality

### Cost Example (10 alerts/hour, 24/7)

- **gpt-4o-mini**: ~$10-15/month
- **gpt-4o**: ~$300-400/month
- **gpt-35-turbo**: ~$30-50/month

## Fallback Strategy

The system **gracefully degrades** if AI is unavailable:

```python
if self.ai_client:
    return await self._calculate_threat_score_ai(alert)
else:
    return await self._calculate_threat_score_deterministic(alert)
```

**Fallback triggers:**
- Missing Azure credentials
- API quota exceeded
- Network connectivity issues
- AI response parsing errors

**In fallback mode:**
- Uses original deterministic algorithms
- Logs warning messages
- System remains fully operational

## API Response Changes

### Enhanced Threat Analysis Response

```json
{
  "threats": [...],
  "risk_score": 0.78,
  "recommendations": [
    "📋 WHAT HAPPENED: ...",
    "⚠️ WHY IT MATTERS: ...",
    "✅ WHAT TO DO NOW: ...",
    "🎚️ SENTRY ADJUSTMENT: ..."
  ],
  "correlations": [...],
  "threshold_recommendation": {
    "action": "LOWER",
    "recommended_value": 0.93,
    "reasoning": "...",
    "confidence": 0.85
  },
  "ai_enhanced": true
}
```

## Monitoring AI Performance

### Log Messages

```
✅ Azure OpenAI client initialized for agentic reasoning
🤖 AI reasoning completed (456 tokens)
🤖 AI Threat Analysis for alert 123: Score=0.87, Confidence=0.92, Stage=Command & Control
🤖 Generated 4 AI-powered recommendations
🎚️ AI Threshold Recommendation: LOWER to 0.93
⚠️ Azure OpenAI initialization failed. Falling back to deterministic analysis.
```

### Metrics to Track

1. **AI Success Rate**: % of requests successfully processed by AI
2. **Token Usage**: Daily/monthly token consumption
3. **Fallback Rate**: How often system falls back to deterministic
4. **Response Time**: AI latency impact (typically +1-3 seconds)
5. **Accuracy**: Compare AI scores vs. actual threat outcomes

## Testing

### Test AI Integration

```bash
cd oracle
python -m pytest tests/test_analytics_ai.py
```

### Manual Testing

```python
from analytics import ThreatAnalyzer
from database import Alert
from models import AlertType, AlertSeverity

analyzer = ThreatAnalyzer()

# Create test alert
alert = Alert(
    source="bridge",
    alert_type=AlertType.DATA_EXFILTRATION,
    severity=AlertSeverity.HIGH,
    title="Unusual data transfer detected",
    description="Large outbound transfer at 2:00 AM",
    network_context={
        "source_ip": "192.168.1.100",
        "dest_ip": "45.33.32.156",
        "bytes_transferred": 5000000,
        "dest_port": 443
    }
)

# Test AI scoring
score = await analyzer.calculate_threat_score(alert)
print(f"AI Threat Score: {score}")
```

## Best Practices

1. **Set appropriate temperature**: 0.3 for focused analysis, 0.7 for creative reasoning
2. **Monitor token usage**: Set up Azure cost alerts
3. **Cache AI responses**: For identical alerts within short time windows
4. **Rate limiting**: Implement exponential backoff for API errors
5. **Human oversight**: AI recommendations should be reviewed by security team before auto-actions

## Security Considerations

- **API Key Protection**: Store in environment variables, never commit to git
- **Data Privacy**: Alert data sent to Azure OpenAI (review Azure privacy policy)
- **Compliance**: Ensure Azure OpenAI meets your regulatory requirements (GDPR, HIPAA, etc.)
- **Access Control**: Limit who can modify AI configuration

## Future Enhancements

- [ ] RAG integration with threat intelligence database
- [ ] Multi-model ensemble (GPT-4o + Phi-4)
- [ ] Fine-tuned models on historical alert data
- [ ] Automated response actions based on AI confidence
- [ ] Natural language query interface for dashboard

## Troubleshooting

### "AI client not available"
- Check `AZURE_OPENAI_API_KEY` is set
- Verify endpoint URL is correct
- Test network connectivity to Azure

### "Failed to parse AI response"
- AI returned non-JSON format
- Increase `AI_MAX_TOKENS` if response truncated
- Check model deployment name

### High API costs
- Reduce `AI_MAX_TOKENS`
- Switch to `gpt-4o-mini` or `gpt-35-turbo`
- Implement request caching
- Increase alert threshold to reduce volume

## Support

For issues or questions:
- GitHub Issues: [cardea/issues](https://github.com/gauciv/cardea/issues)
- Documentation: `/docs/`
- Azure OpenAI Docs: [learn.microsoft.com/azure/ai-services/openai](https://learn.microsoft.com/en-us/azure/ai-services/openai/)
