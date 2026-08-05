"""
clients/abuseipdb.py
Tanak klijent za AbuseIPDB API (samo IP provere).
Dokumentacija: https://docs.abuseipdb.com/
"""

import requests

BASE_URL = "https://api.abuseipdb.com/api/v2/check"


class AbuseIPDBError(Exception):
    pass


class AbuseIPDBClient:
    def __init__(self, api_key: str):
        if not api_key:
            raise AbuseIPDBError("AbuseIPDB API ključ nije postavljen (ABUSEIPDB_API_KEY).")
        self.api_key = api_key
        self.headers = {"Key": api_key, "Accept": "application/json"}

    def check_ip(self, ip: str, max_age_days: int = 90) -> dict:
        params = {"ipAddress": ip, "maxAgeInDays": max_age_days, "verbose": ""}
        try:
            resp = requests.get(BASE_URL, headers=self.headers, params=params, timeout=15)
        except requests.RequestException as e:
            raise AbuseIPDBError(f"Mrežna greška prilikom poziva AbuseIPDB API-ja: {e}")

        if resp.status_code == 401:
            raise AbuseIPDBError("Nevažeći AbuseIPDB API ključ.")
        if resp.status_code == 429:
            raise AbuseIPDBError("AbuseIPDB rate limit dostignut.")
        if not resp.ok:
            raise AbuseIPDBError(f"AbuseIPDB API greška {resp.status_code}: {resp.text[:200]}")

        return resp.json()

    @staticmethod
    def summarize(raw: dict) -> dict:
        data = raw.get("data", {})
        if not data:
            return {"found": False}

        return {
            "found": True,
            "abuse_confidence_score": data.get("abuseConfidenceScore"),
            "total_reports": data.get("totalReports"),
            "num_distinct_users": data.get("numDistinctUsers"),
            "country_code": data.get("countryCode"),
            "isp": data.get("isp"),
            "domain": data.get("domain"),
            "usage_type": data.get("usageType"),
            "is_tor": data.get("isTor"),
            "is_whitelisted": data.get("isWhitelisted"),
            "last_reported_at": data.get("lastReportedAt"),
        }
