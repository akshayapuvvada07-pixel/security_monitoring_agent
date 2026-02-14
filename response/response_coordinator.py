"""Response coordinator to handle alerts from detection engines."""
import json
from typing import List, Dict, Any
from response.alerter import send_alerts
from config import settings


class ResponseCoordinator:
    """Orchestrates responses to detected threats and anomalies."""

    def __init__(self):
        pass

    def handle(self, rule_alerts: List[Dict[str, Any]], anomaly_alerts: List[Dict[str, Any]]) -> None:
        """Handle detected threats by logging and optionally sending alerts.

        Args:
            rule_alerts: List of alerts from rule engine.
            anomaly_alerts: List of alerts from anomaly detector.
        """
        # Combine all alerts
        all_alerts = rule_alerts + anomaly_alerts

        if not all_alerts:
            print("No threats detected.")
            return

        print(f"\nHandling {len(all_alerts)} alert(s)...")

        # Log combined alerts to stdout
        for i, alert in enumerate(all_alerts, 1):
            print(f"  [{i}] {json.dumps(alert)}")

        # Attempt to send via webhook if configured
        webhook = settings.ALERT_WEBHOOK
        api_key = settings.API_KEY
        if webhook:
            success, msg = send_alerts(all_alerts, webhook_url=webhook, api_key=api_key)
            if success:
                print(f"✓ Alerts sent: {msg}")
            else:
                print(f"✗ Failed to send alerts: {msg}")
        else:
            print("(No webhook configured; alerts will be logged locally only)")
