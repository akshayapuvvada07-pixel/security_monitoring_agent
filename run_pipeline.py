import json
import sys
from pathlib import Path

# Ensure project root is on sys.path when running this script directly
ROOT = Path(__file__).resolve().parents[0]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from collector.log_collector import LogCollector
from processor.parser import LogParser
from processor.scaler import ScaleDown
from detection.anomaly_detector import AnomalyDetector
from response.alerter import send_alerts
from config import settings


def main():
    import argparse
    p = argparse.ArgumentParser(description='Run log collection -> parsing -> detection pipeline')
    p.add_argument('--api-key', help='API key for collector (overrides env var or config/api_key.txt)')
    p.add_argument('--n-sigma', type=float, default=None, help='Heuristic n_sigma for anomaly detector (fallback)')
    p.add_argument('--out', default=str(Path(__file__).resolve().parents[0] / 'data' / 'alerts.json'), help='Output alerts file')
    args = p.parse_args()

    # Use CLI arg if provided, else fall back to config.settings (which reads env var or api_key.txt)
    api_key_to_use = args.api_key or settings.API_KEY
    collector = LogCollector(api_key=api_key_to_use)
    try:
        logs = collector.collect_logs()
    except Exception as e:
        print(f"Failed to collect logs: {e}")
        raise SystemExit(1)

    parser = LogParser()
    parsed = parser.parse(logs)

    scaler = ScaleDown()
    # scaler.compress_logs expects a pandas-like object; handle list fallback
    if hasattr(parsed, 'drop_duplicates'):
        compressed = scaler.compress_logs(parsed)
    else:
        # dedupe list of dicts
        seen = set()
        unique = []
        for r in parsed:
            key = json.dumps(r, sort_keys=True, default=str)
            if key in seen:
                continue
            seen.add(key)
            unique.append(r)
        compressed = unique

    # Instantiate detector; pass n_sigma if provided
    if args.n_sigma is not None:
        detector = AnomalyDetector(n_sigma=args.n_sigma)
    else:
        detector = AnomalyDetector()

    # Aggregate into per-IP metrics expected by the detector
    agg = {}
    for r in (compressed if isinstance(compressed, list) else list(compressed)):
        ip = r.get('source_ip') or r.get('ip') or 'unknown'
        entry = agg.setdefault(ip, {'ip': ip, 'failed_logins': 0, 'requests': 0})
        if r.get('event') == 'failed_login':
            entry['failed_logins'] += 1
        entry['requests'] += 1

    rows = list(agg.values())
    anomalies = detector.detect(rows)

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, 'w', encoding='utf-8') as fh:
        json.dump(anomalies, fh, indent=2)

    print(f"Wrote {len(anomalies)} alert(s) to {out_path}")
    print(json.dumps(anomalies, indent=2))

    # Attempt to send alerts via webhook if configured
    webhook = settings.ALERT_WEBHOOK
    api_key = settings.API_KEY
    success, msg = send_alerts(anomalies, webhook_url=webhook, api_key=api_key)
    if success:
        print(f"Alerts posted to webhook: {msg}")
    else:
        print(f"Alerts not posted: {msg}")


if __name__ == '__main__':
    main()
