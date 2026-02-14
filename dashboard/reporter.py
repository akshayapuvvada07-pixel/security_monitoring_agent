"""Reporter to generate summaries of security monitoring results."""
import json
from typing import List, Dict, Any
from pathlib import Path


class Reporter:
    """Generate reports on detected threats and anomalies."""

    def __init__(self, output_dir: str | None = None):
        """Initialize the reporter.

        Args:
            output_dir: Directory to write reports to (defaults to data/).
        """
        self.output_dir = Path(output_dir) if output_dir else Path(__file__).resolve().parents[1] / 'data'
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate(self, rule_alerts: List[Dict[str, Any]], anomaly_alerts: List[Dict[str, Any]]) -> None:
        """Generate a report of detected threats and anomalies.

        Args:
            rule_alerts: List of alerts from rule engine.
            anomaly_alerts: List of alerts from anomaly detector.
        """
        total_alerts = len(rule_alerts) + len(anomaly_alerts)

        # Create a summary report
        report = {
            "timestamp": self._get_timestamp(),
            "summary": {
                "rule_alerts": len(rule_alerts),
                "anomaly_alerts": len(anomaly_alerts),
                "total_alerts": total_alerts,
            },
            "rule_alerts": rule_alerts,
            "anomaly_alerts": anomaly_alerts,
        }

        # Write report to file
        report_file = self.output_dir / "report.json"
        with open(report_file, 'w', encoding='utf-8') as fh:
            json.dump(report, fh, indent=2, default=str)

        print(f"\n📊 Report generated: {report_file}")
        print(f"  Rule Alerts: {len(rule_alerts)}")
        print(f"  Anomaly Alerts: {len(anomaly_alerts)}")
        print(f"  Total: {total_alerts}")

    def _get_timestamp(self) -> str:
        """Get current ISO timestamp."""
        from datetime import datetime
        return datetime.utcnow().isoformat() + "Z"
