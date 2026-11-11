from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def fetch_pfSense_candidates(api_key: str | None = None, timeout: int = 25) -> dict:
    """Fetch candidate CVE records mentioning pfSense from NVD.

    This is discovery only. NVD keyword matches must be reviewed against the
    vendor advisory and affected release/package details before classification.
    """
    params = urllib.parse.urlencode({"keywordSearch": "pfSense", "resultsPerPage": 100})
    request = urllib.request.Request(f"{NVD_API_URL}?{params}", headers={"User-Agent": "pfSense-Security-Orchestrator/0.1"})
    if api_key:
        request.add_header("apiKey", api_key)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"NVD API returned HTTP {exc.code}: {exc.reason}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Unable to reach NVD API: {exc.reason}") from exc

    candidates = []
    for entry in payload.get("vulnerabilities", []):
        cve = entry.get("cve", {})
        descriptions = cve.get("descriptions", [])
        english = next((item.get("value", "") for item in descriptions if item.get("lang") == "en"), "")
        references = [item.get("url") for item in cve.get("references", []) if item.get("url")]
        candidates.append({
            "id": cve.get("id"),
            "published": cve.get("published"),
            "last_modified": cve.get("lastModified"),
            "description": english,
            "references": references,
            "review_status": "unreviewed_candidate",
        })

    return {
        "source": NVD_API_URL,
        "query": "pfSense",
        "retrieved_at": datetime.now(timezone.utc).isoformat(),
        "total_results": payload.get("totalResults", len(candidates)),
        "candidates": candidates,
    }


def save_candidate_feed(data: dict, path: Path = Path("data/nvd_candidates.json")) -> Path:
    path = path.expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = json.dumps(data, indent=2, sort_keys=True).encode("utf-8")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(encoded)
        handle.flush()
        os.fsync(handle.fileno())
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return path
