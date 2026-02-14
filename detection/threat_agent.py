import sys
from pathlib import Path

# Ensure project root is on sys.path when running this file directly
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from detection.rule_engine import RuleEngine
from detection.anomaly_detector import AnomalyDetector


class ThreatAgent:

    def __init__(self):
        self.rules = RuleEngine()
        self.anomaly = AnomalyDetector()

    def analyze(self, df):
        # `RuleEngine.check_rules` expects a pandas-like object with
        # `iterrows()`. `AnomalyDetector.detect` can accept a list of dicts.
        rows = df

        # If rows is a list of dicts, adapt for rule engine
        if isinstance(rows, list):
            try:
                import pandas as _pd  # type: ignore
                rule_df = _pd.DataFrame(rows)
            except Exception:
                class _Row:
                    def __init__(self, d):
                        self._d = d
                    def __getitem__(self, key):
                        return self._d.get(key)

                class _FakeDF:
                    def __init__(self, rows):
                        self._rows = rows
                    def iterrows(self):
                        for i, r in enumerate(self._rows):
                            yield i, _Row(r)

                rule_df = _FakeDF(rows)

        else:
            rule_df = rows

        rule_alerts = self.rules.check_rules(rule_df)
        anomaly_alerts = self.anomaly.detect(rows)

        return rule_alerts, anomaly_alerts


if __name__ == '__main__':
    # Simple demo: aggregate sample logs and run analysis
    import json
    sample = Path(__file__).resolve().parents[1] / 'data' / 'sample_logs.json'
    if not sample.exists():
        print(f"No sample logs found at {sample}")
        raise SystemExit(1)

    with open(sample, 'r', encoding='utf-8') as fh:
        logs = json.load(fh)

    # simple aggregation into per-ip metrics expected by RuleEngine/AnomalyDetector
    agg = {}
    for r in logs:
        ip = r.get('source_ip') or r.get('ip') or 'unknown'
        entry = agg.setdefault(ip, {'ip': ip, 'failed_logins': 0, 'requests': 0})
        if r.get('event') == 'failed_login':
            entry['failed_logins'] += 1
        entry['requests'] += 1

    rows = list(agg.values())
    ta = ThreatAgent()
    rule_alerts, anomaly_alerts = ta.analyze(rows)
    print('Rule alerts:', json.dumps(rule_alerts, indent=2))
    print('Anomaly alerts:', json.dumps(anomaly_alerts, indent=2))
