"""
clients/virustotal.py
Tanak klijent za VirusTotal API v3 (ip_addresses, domains, files endpoints).
Dokumentacija: https://docs.virustotal.com/reference/overview
"""

import requests

BASE_URL = "https://www.virustotal.com/api/v3"


class VirusTotalError(Exception):
    pass


class VirusTotalClient:
    def __init__(self, api_key: str):
        if not api_key:
            raise VirusTotalError("VirusTotal API ključ nije postavljen (VT_API_KEY).")
        self.api_key = api_key
        self.headers = {"x-apikey": api_key}

    def _get(self, endpoint: str) -> dict:
        url = f"{BASE_URL}/{endpoint}"
        try:
            resp = requests.get(url, headers=self.headers, timeout=15)
        except requests.RequestException as e:
            raise VirusTotalError(f"Mrežna greška prilikom poziva VirusTotal API-ja: {e}")

        if resp.status_code == 401:
            raise VirusTotalError("Nevažeći VirusTotal API ključ.")
        if resp.status_code == 404:
            return {"not_found": True}
        if resp.status_code == 429:
            raise VirusTotalError("VirusTotal rate limit dostignut (free tier: 4 zahteva/min).")
        if not resp.ok:
            raise VirusTotalError(f"VirusTotal API greška {resp.status_code}: {resp.text[:200]}")

        return resp.json()

    def check_ip(self, ip: str) -> dict:
        return self._get(f"ip_addresses/{ip}")

    def check_domain(self, domain: str) -> dict:
        return self._get(f"domains/{domain}")

    def check_hash(self, file_hash: str) -> dict:
        return self._get(f"files/{file_hash}")

    @staticmethod
    def summarize(raw: dict) -> dict:
        """Izvlači ključne podatke iz sirovog VT JSON odgovora u jednostavan dict."""
        if raw.get("not_found"):
            return {"found": False}

        attrs = raw.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})

        return {
            "found": True,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "reputation": attrs.get("reputation"),
            "country": attrs.get("country"),
            "as_owner": attrs.get("as_owner"),
            "categories": attrs.get("categories"),
            "type_description": attrs.get("type_description"),
            "meaningful_name": attrs.get("meaningful_name"),
            "last_analysis_date": attrs.get("last_analysis_date"),
        }
