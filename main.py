# ===============================
# Security Monitoring Agent
# Main Orchestrator
# ===============================

import sys
from pathlib import Path

# Ensure project root is on sys.path
ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from collector.log_collector import LogCollector
from processor.parser import LogParser
from processor.scaler import ScaleDown
from detection.threat_agent import ThreatAgent
from response.response_coordinator import ResponseCoordinator
from dashboard.reporter import Reporter
from config import settings


def main():
    import argparse
    p = argparse.ArgumentParser(description='Security Monitoring Agent')
    p.add_argument('--api-key', help='API key (overrides env var or config/api_key.txt)')
    args = p.parse_args()

    print("\n=== Security Monitoring Agent Started ===\n")

    # 1️⃣ Collect Logs
    api_key_to_use = args.api_key or settings.API_KEY
    collector = LogCollector(api_key=api_key_to_use)
    logs = collector.collect_logs()
    print(f"Collected {len(logs)} logs")

    # 2️⃣ Parse Logs
    parser = LogParser()
    parsed_logs = parser.parse(logs)
    print("Logs parsed successfully")

    # 3️⃣ Compress / Scale Down Logs
    scaler = ScaleDown()
    try:
        processed_logs = scaler.compress_logs(parsed_logs)
        log_count = len(processed_logs) if hasattr(processed_logs, '__len__') else len(list(processed_logs))
    except Exception as e:
        print(f"Compression skipped: {e}. Using parsed logs directly.")
        processed_logs = parsed_logs
        log_count = len(list(processed_logs)) if isinstance(processed_logs, list) else len(processed_logs)
    print(f"Logs after compression: {log_count}")

    # 4️⃣ Threat Detection
    # Aggregate raw logs into per-IP metrics expected by threat agent
    agg = {}
    for r in (processed_logs if isinstance(processed_logs, list) else list(processed_logs)):
        ip = r.get('source_ip') or r.get('ip') or 'unknown'
        entry = agg.setdefault(ip, {'ip': ip, 'failed_logins': 0, 'requests': 0})
        if r.get('event') == 'failed_login':
            entry['failed_logins'] += 1
        entry['requests'] += 1

    threat_agent = ThreatAgent()
    rule_alerts, anomaly_alerts = threat_agent.analyze(list(agg.values()))

    print(f"Rule Alerts Found: {len(rule_alerts)}")
    print(f"Anomalies Found: {len(anomaly_alerts)}")

    # 5️⃣ Response Coordination
    responder = ResponseCoordinator()
    responder.handle(rule_alerts, anomaly_alerts)

    # 6️⃣ Reporting / Dashboard
    reporter = Reporter()
    reporter.generate(rule_alerts, anomaly_alerts)

    print("\n=== Monitoring Completed ===\n")


# Entry Point
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nMonitoring interrupted by user.")
        raise SystemExit(0)
    except Exception as e:
        print(f"\nError: {e}")
        raise SystemExit(1)
    print("test push")
