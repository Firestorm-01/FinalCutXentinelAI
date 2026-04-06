# XentinelAI — Automated Security Review Agent

Scans code, IaC, and IAM policies for vulnerabilities. Uses AWS Bedrock (Claude 3 Sonnet) for AI remediation with Groq as fallback.

## Quick Setup

```bash
# 1. Install Python deps
pip install -r requirements.txt

# 2. Install scanner tools
pip install semgrep checkov

# 3. Copy and fill env vars
cp .env.example .env

# 4. Run the API
uvicorn main:app --reload --port 8000
```

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/scan/github` | Scan a public GitHub repo |
| POST | `/scan/upload` | Scan an uploaded .zip |
| GET  | `/scan/{id}` | Get scan results |
| GET  | `/scan/{id}/report` | Download JSON report |
| GET  | `/scans` | List recent scans |

## Example

```bash
curl -X POST http://localhost:8000/scan/github \
  -H "Content-Type: application/json" \
  -d '{"github_url": "https://github.com/your/repo"}'
```

## AWS Pre-Setup Checklist

1. Request Bedrock Claude 3 Sonnet access: AWS Console → Bedrock → Model Access
2. Create DynamoDB table: `xentinel-scans` (partition key: `scan_id`)  
3. Create SNS topic: `xentinel-alerts` → add your email subscriber
4. Create IAM user with: `AmazonBedrockFullAccess`, `AmazonDynamoDBFullAccess`, `AmazonSNSFullAccess`
5. Export credentials to `.env`

## Expose locally for demo

```bash
# Install ngrok, then:
ngrok http 8000
# Share the https URL with judges
```

test case links:
https://github.com/bridgecrewio/terragoat
https://github.com/digininja/DVWA
command to run:
source venv/bin/activate
python -m uvicorn main:app --port 8000
  

python 3.11 fix:
deactivate
rm -rf venv
python3.11 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

