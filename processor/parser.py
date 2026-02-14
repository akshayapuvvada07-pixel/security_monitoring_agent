import json
from datetime import datetime
from typing import List, Dict, Any

try:
    import pandas as pd
    _HAS_PANDAS = True
except Exception:
    pd = None
    _HAS_PANDAS = False


class LogParser:
    def parse(self, logs: List[Dict[str, Any]]):
        """Parse a list of log dicts.

        If pandas is available, return a DataFrame. Otherwise return a
        list of normalized dicts with parsed timestamps.
        """
        if _HAS_PANDAS:
            df = pd.DataFrame(logs)
            df['timestamp'] = pd.to_datetime(df['timestamp'])
            df.fillna("unknown", inplace=True)
            return df

        # Fallback implementation without pandas
        normalized = []
        for entry in logs:
            e = dict(entry)  # shallow copy
            ts = e.get('timestamp')
            try:
                e['timestamp'] = datetime.fromisoformat(ts.replace('Z', '+00:00')) if ts else None
            except Exception:
                e['timestamp'] = None

            # fill missing values with the string 'unknown'
            for k, v in list(e.items()):
                if v is None:
                    e[k] = 'unknown'

            normalized.append(e)

        return normalized


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Test LogParser')
    parser.add_argument('--file', '-f', default=None, help='JSON file of logs to parse')
    args = parser.parse_args()

    if args.file:
        with open(args.file, 'r', encoding='utf-8') as fh:
            logs = json.load(fh)
    else:
        # simple default sample
        logs = [
            {"timestamp": "2026-02-14T10:00:00Z", "event": "failed_login", "username": "jdoe"},
            {"timestamp": "2026-02-14T10:05:23Z", "event": "file_uploaded", "filename": "report.pdf"}
        ]

    lp = LogParser()
    out = lp.parse(logs)
    if _HAS_PANDAS:
        print(out.to_string(index=False))
    else:
        print(json.dumps(out, default=str, indent=2))
