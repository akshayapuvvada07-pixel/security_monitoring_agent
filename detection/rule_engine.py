class RuleEngine:

    def check_rules(self, df):
        alerts = []

        for _, row in df.iterrows():
            failed_logins = row.get("failed_logins") if hasattr(row, "get") else row["failed_logins"]
            ip = row.get("ip") if hasattr(row, "get") else row["ip"]
            
            # Handle None/unknown values
            if failed_logins is None or failed_logins == "unknown":
                failed_logins = 0
            else:
                try:
                    failed_logins = int(failed_logins)
                except (TypeError, ValueError):
                    failed_logins = 0

            # Check rule: brute force (> 5 failed logins)
            if failed_logins > 5:
                alerts.append({
                    "type": "Brute Force",
                    "ip": ip,
                    "failed_logins": failed_logins
                })

        return alerts
