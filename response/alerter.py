import json
from typing import List, Dict, Any, Tuple
from urllib import request, error


def send_alerts(alerts: List[Dict[str, Any]], webhook_url: str | None = None, api_key: str | None = None) -> Tuple[bool, str]:
    """Send alerts to webhook_url via POST with JSON body.

    Returns (success, message).
    """
    if not webhook_url:
        return False, "No webhook configured"

    data = json.dumps(alerts).encode("utf-8")
    req = request.Request(webhook_url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    if api_key:
        req.add_header("Authorization", f"Bearer {api_key}")

    try:
        with request.urlopen(req, timeout=10) as resp:
            status = resp.getcode()
            body = resp.read().decode("utf-8", errors="ignore")
            return True, f"POST {webhook_url} -> {status}: {body}"
    except error.HTTPError as e:
        return False, f"HTTP error {e.code}: {e.reason}"
    except error.URLError as e:
        return False, f"URL error: {e.reason}"
    except Exception as e:
        return False, f"Unexpected error: {e}"
