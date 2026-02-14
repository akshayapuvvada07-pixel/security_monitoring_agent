import argparse
import json
import os
import sys
from pathlib import Path

# Ensure project root is on sys.path so `config` can be imported when running
# this file directly (python collector/log_collector.py)
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from config.settings import LOG_PATH


class LogCollector:
    def __init__(self, api_key: str | None = None):
        self.api_key = api_key

    def collect_logs(self):
        path = Path(LOG_PATH)
        if not path.is_absolute():
            path = (ROOT / path).resolve()

        with open(path, "r", encoding="utf-8") as f:
            logs = json.load(f)
        return logs


def _mask_key(key: str) -> str:
    if not key:
        return ""
    if len(key) <= 8:
        return "*" * len(key)
    return key[:4] + "*" * (len(key) - 8) + key[-4:]


def main() -> int:
    p = argparse.ArgumentParser(description="Collect logs and optionally use an API key")
    p.add_argument("--api-key", dest="api_key", help="API key (or set API_KEY env var)")
    args = p.parse_args()

    api_key = args.api_key or os.environ.get("API_KEY")

    collector = LogCollector(api_key=api_key)
    if api_key:
        print(f"Using API key: {_mask_key(api_key)}")

    try:
        logs = collector.collect_logs()
    except FileNotFoundError:
        print(f"Log file not found: {LOG_PATH}")
        return 1
    except json.JSONDecodeError as e:
        print(f"Failed to parse JSON from {LOG_PATH}: {e}")
        return 1
    except Exception as e:
        print(f"Unexpected error while collecting logs: {e}")
        return 1

    print(json.dumps(logs, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
