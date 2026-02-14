import os
from pathlib import Path


def _env_or_default(name, default=None):
	v = os.environ.get(name)
	return v if v is not None else default


# Paths and thresholds (can be overridden via environment variables)
LOG_PATH = _env_or_default("LOG_PATH", "data/sample_logs.json")
ANOMALY_THRESHOLD = float(_env_or_default("ANOMALY_THRESHOLD", 0.6))
ALERT_EMAIL = _env_or_default("ALERT_EMAIL", "soc_team@example.com")

# API key should be provided via the environment for security
API_KEY = _env_or_default("API_KEY", None)

# Optional webhook to POST alerts to (takes precedence over email)
ALERT_WEBHOOK = _env_or_default("ALERT_WEBHOOK", None)

# If `API_KEY` was not provided via environment, attempt to read from
# `config/api_key.txt` (convenience file; keep it private).
if not API_KEY:
	try:
		api_file = Path(__file__).resolve().parent / 'api_key.txt'
		if api_file.exists():
			API_KEY = api_file.read_text(encoding='utf-8').strip() or None
	except Exception:
		API_KEY = None


def _mask_key(key: str | None) -> str:
	if not key:
		return ""
	if len(key) <= 8:
		return "*" * len(key)
	return key[:4] + "*" * (len(key) - 8) + key[-4:]


if __name__ == '__main__':
	# Print configuration values with sensitive fields masked
	print(f"LOG_PATH = {LOG_PATH}")
	print(f"ANOMALY_THRESHOLD = {ANOMALY_THRESHOLD}")
	print(f"ALERT_EMAIL = {ALERT_EMAIL}")
	print(f"API_KEY = {_mask_key(API_KEY)}")
