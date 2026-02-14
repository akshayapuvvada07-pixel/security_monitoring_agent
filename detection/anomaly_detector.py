"""Anomaly detection with a sklearn IsolationForest when available.

If scikit-learn is unavailable, a lightweight fallback heuristic is used:
flag rows where any numeric feature is more than `n_sigma` standard
deviations away from the mean.
"""
from typing import List, Dict, Any

try:
    import numpy as np
    _HAS_NUMPY = True
except Exception:
    np = None
    _HAS_NUMPY = False

try:
    from sklearn.ensemble import IsolationForest
    _HAS_SKLEARN = True
except Exception:
    IsolationForest = None
    _HAS_SKLEARN = False


class AnomalyDetector:
    def __init__(self, contamination: float = 0.1, n_sigma: float = 3.0):
        self.contamination = contamination
        self.n_sigma = n_sigma
        self.model = None
        if _HAS_SKLEARN:
            self.model = IsolationForest(contamination=self.contamination)

    def detect(self, df) -> List[Dict[str, Any]]:
        """Detect anomalies in `df` and return list of record dicts.

        `df` is expected to be a pandas DataFrame-like object with
        numeric columns `failed_logins` and `requests`. If pandas is not
        available upstream, callers may pass any object supporting
        item access by column names and row iteration.
        """
        # Extract numeric features; if df is a list of dicts, convert
        # to numpy arrays on the fly.
        try:
            features = df[["failed_logins", "requests"]]
        except Exception:
            # fallback: attempt to build feature array from iterable
            rows = list(df)
            if _HAS_NUMPY:
                features = np.array([[r.get("failed_logins", 0), r.get("requests", 0)] for r in rows])
            else:
                features = [[r.get("failed_logins", 0), r.get("requests", 0)] for r in rows]

        if _HAS_SKLEARN and self.model is not None:
            # sklearn path expects a 2D array-like
            try:
                self.model.fit(features)
                preds = self.model.predict(features)
                # -1 indicates anomaly in IsolationForest
                mask = preds == -1
            except Exception:
                # If sklearn fails for some reason, fall back to heuristic
                mask = self._heuristic_mask(features)
        else:
            mask = self._heuristic_mask(features)

        # Build result list of anomaly records
        anomalies = []
        # support both pandas-like indexing and numpy-like
        if hasattr(features, "iloc"):
            # pandas DataFrame/NDFrame
            for idx, is_anom in enumerate(mask):
                if is_anom:
                    anomalies.append(df.iloc[idx].to_dict())
        else:
            # features is numpy array and we have original rows
            try:
                rows = list(df)
            except Exception:
                # if df was pandas but features conversion failed earlier,
                # attempt to iterate df directly
                rows = []
            for idx, is_anom in enumerate(mask):
                if is_anom and idx < len(rows):
                    anomalies.append(rows[idx])

        return anomalies

    def _heuristic_mask(self, features: Any):
        """Return boolean mask where rows are True if any feature value
        deviates from the mean by more than `n_sigma` standard deviations.

        Supports numpy arrays (when available) or plain Python lists.
        """
        # If numpy is available, use vectorized computation
        if _HAS_NUMPY:
            arr = np.asarray(features)
            if arr.ndim == 1:
                arr = arr.reshape(-1, 1)
            means = np.nanmean(arr, axis=0)
            stds = np.nanstd(arr, axis=0)
            stds[stds == 0] = 1e-8
            z = np.abs((arr - means) / stds)
            mask = (z > self.n_sigma).any(axis=1)
            return mask

        # Pure-Python fallback: features expected as iterable of iterables
        rows = [list(r) for r in features]
        if not rows:
            return []
        cols = list(zip(*rows))
        means = []
        stds = []
        for c in cols:
            vals = [v if v is not None else 0 for v in c]
            n = len(vals)
            mean = sum(vals) / n
            means.append(mean)
            # population std
            var = sum((v - mean) ** 2 for v in vals) / n
            std = var ** 0.5
            if std == 0:
                std = 1e-8
            stds.append(std)

        mask = []
        for r in rows:
            is_anom = False
            for i, v in enumerate(r):
                if v is None:
                    continue
                z = abs((v - means[i]) / stds[i])
                if z > self.n_sigma:
                    is_anom = True
                    break
            mask.append(is_anom)
        return mask


if __name__ == '__main__':
    # Simple CLI demo that reads sample logs, aggregates minimal metrics,
    # and prints detected anomalies.
    import json
    import argparse
    from pathlib import Path

    p = argparse.ArgumentParser(description='Demo AnomalyDetector')
    p.add_argument('--file', '-f', help='JSON file with logs (list of dicts)')
    args = p.parse_args()

    # locate sample file by default
    sample = Path(__file__).resolve().parents[1] / 'data' / 'sample_logs.json'
    file = Path(args.file) if args.file else sample

    if not file.exists():
        print(f"No input file: {file}")
        raise SystemExit(1)

    with open(file, 'r', encoding='utf-8') as fh:
        logs = json.load(fh)

    # Build simple aggregation: count failed_logins and requests per ip
    agg = {}
    for r in logs:
        ip = r.get('source_ip') or r.get('ip') or 'unknown'
        entry = agg.setdefault(ip, {'ip': ip, 'failed_logins': 0, 'requests': 0})
        if r.get('event') == 'failed_login':
            entry['failed_logins'] += 1
        entry['requests'] += 1

    rows = list(agg.values())
    detector = AnomalyDetector()
    anomalies = detector.detect(rows)
    print(json.dumps(anomalies, indent=2))
