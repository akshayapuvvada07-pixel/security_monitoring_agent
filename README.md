# Security Monitoring Agent

A modular Python-based security monitoring system that collects logs, detects anomalies, identifies threats, and sends alerts.

## Features

- **Log Collection**: Gather logs from JSON sources with API key support.
- **Log Parsing**: Normalize timestamps and handle missing values.
- **Log Compression**: Deduplicate events to reduce noise.
- **Anomaly Detection**: Uses scikit-learn's IsolationForest (or a lightweight fallback heuristic) to flag unusual activity.
- **Rule Engine**: Checks for known threat patterns (e.g., brute-force attacks).
- **Unified Threat Analysis**: Combines rule-based and anomaly detection.
- **Alert Sending**: POST alerts to a webhook endpoint with API key authentication.

## Quick Start

### 1. Install Dependencies

```powershell
C:/Users/puvva/python.exe -m pip install --upgrade pip
C:/Users/puvva/python.exe -m pip install -r security_monitoring_agent/requirements.txt
```

### 2. Configure API Key

#### Option A: Use `config/api_key.txt` (Convenience)
Edit [config/api_key.txt](config/api_key.txt) and replace `PASTE_YOUR_API_KEY_HERE` with your real API key:

```
your_actual_api_key_here
```

**Important**: Keep this file private. It is listed in `.gitignore` to prevent accidental commits.

#### Option B: Use Environment Variable (More Secure)
```powershell
$env:API_KEY = 'your_actual_api_key_here'
C:/Users/puvva/python.exe security_monitoring_agent/run_pipeline.py
```

### 3. Configure Webhook (Optional)

To send alerts to a service:

```powershell
$env:ALERT_WEBHOOK = 'https://your-webhook-endpoint.com/alerts'
C:/Users/puvva/python.exe security_monitoring_agent/run_pipeline.py
```

The API key will be sent as a Bearer token in the `Authorization` header.

### 4. Run the Pipeline

```powershell
C:/Users/puvva/python.exe security_monitoring_agent/run_pipeline.py
```

This will:
1. Collect logs from `data/sample_logs.json`.
2. Parse and normalize timestamps.
3. Detect anomalies using machine learning.
4. Write alerts to `data/alerts.json`.
5. Optionally POST alerts to the webhook.

## Configuration

Edit `config/settings.py` or set environment variables:

| Variable | Default | Purpose |
|----------|---------|---------|
| `API_KEY` | `config/api_key.txt` | API key for authentication |
| `LOG_PATH` | `data/sample_logs.json` | Path to log input file |
| `ANOMALY_THRESHOLD` | `0.6` | Anomaly detection threshold |
| `ALERT_EMAIL` | `soc_team@example.com` | Email for alerts (future use) |
| `ALERT_WEBHOOK` | None | Webhook URL for alerts |

## Security Best Practices

⚠️ **CRITICAL**: Never commit `config/api_key.txt` to version control. The file is in `.gitignore`, but verify before pushing:

```bash
git check-ignore config/api_key.txt  # Should print the file path if ignored
```

1. **API Key Storage**:
   - Prefer environment variables over `config/api_key.txt` when possible.
   - If using the file, store it in a secure location with restricted file permissions.
   - Rotate API keys regularly.

2. **Webhook Security**:
   - Use HTTPS (not HTTP) for webhook endpoints.
   - Include authentication (API key) in the Authorization header (Bearer token).
   - Validate webhook responses.

3. **Log Data**:
   - Ensure log files do not contain sensitive data (passwords, PII, etc.).
   - Restrict access to `data/` directory.

4. **Dependencies**:
   - Keep Python packages updated: `pip install --upgrade pip setuptools wheel`
   - Use a virtual environment to isolate dependencies.

## Project Structure

```
security_monitoring_agent/
├── collector/           # Log collection
│   └── log_collector.py
├── processor/           # Data processing
│   ├── parser.py        # Parse & normalize logs
│   └── scaler.py        # Deduplicate events
├── detection/           # Threat detection
│   ├── anomaly_detector.py  # ML-based anomaly detection
│   ├── rule_engine.py       # Pattern-based rules
│   └── threat_agent.py      # Combined analysis
├── response/            # Alert handling
│   └── alerter.py       # Send alerts via webhook
├── config/
│   ├── settings.py      # Configuration (env var overrides)
│   └── api_key.txt      # Your API key (private, in .gitignore)
├── data/
│   ├── sample_logs.json # Sample log input
│   └── alerts.json      # Generated alerts
├── run_pipeline.py      # Main orchestrator
├── requirements.txt     # Python dependencies
├── .gitignore          # Git ignore rules
└── README.md           # This file
```

## Running Individual Components

### Log Collector
```powershell
C:/Users/puvva/python.exe security_monitoring_agent/collector/log_collector.py --api-key your_key
```

### Parser
```powershell
C:/Users/puvva/python.exe security_monitoring_agent/processor/parser.py --file data/sample_logs.json
```

### Anomaly Detector
```powershell
C:/Users/puvva/python.exe security_monitoring_agent/detection/anomaly_detector.py --file data/sample_logs.json
```

### Threat Agent (Combined)
```powershell
C:/Users/puvva/python.exe security_monitoring_agent/detection/threat_agent.py
```

## Testing

The pipeline includes a sample dataset with an injected anomaly (IP `198.51.100.7` with 7 failed logins). Run the pipeline to verify it detects this anomaly.

## Troubleshooting

- **"No module named 'pandas'"**: Install dependencies: `pip install -r requirements.txt`
- **"No webhook configured"**: Set `ALERT_WEBHOOK` env var to send alerts.
- **API_KEY not found**: Ensure `config/api_key.txt` exists or set `API_KEY` env var.

## Dependencies

- `pandas` - Data manipulation (optional; fallback without it)
- `scikit-learn` - Machine learning for anomaly detection (optional; fallback without it)
- `numpy` - Numerical computing (optional; fallback without it)
- `requests` - HTTP library (optional; uses urllib by default)

All dependencies are listed in `requirements.txt`.

## License

Internal use only.
