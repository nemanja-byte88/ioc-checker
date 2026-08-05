#!/usr/bin/env python3
"""
ioc_checker.py
IOC Checker — CLI alat koji proverava IP adrese, domene i fajl hash-eve (MD5/SHA1/SHA256)
kroz VirusTotal i AbuseIPDB, i generiše čitljiv threat-intel report.

Primeri upotrebe:
    python ioc_checker.py 8.8.8.8
    python ioc_checker.py evil-domain.com
    python ioc_checker.py 44d88612fea8a8f36de82e1278abb02f
    python ioc_checker.py --file iocs.txt --output report.json
    python ioc_checker.py --file iocs.txt --output report.md --format markdown
"""

import argparse
import json
import sys
import time
from datetime import datetime, timezone

from dotenv import load_dotenv
import os

from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from utils import detect_ioc_type, read_iocs_from_file, IOCType
from clients.virustotal import VirusTotalClient, VirusTotalError
from clients.abuseipdb import AbuseIPDBClient, AbuseIPDBError

console = Console()

# VirusTotal free tier: 4 zahteva/min -> bezbedan razmak između poziva
VT_RATE_LIMIT_DELAY = 16


def get_verdict(vt_summary: dict, abuse_summary: dict | None) -> str:
    """Jednostavna heuristika za brzi verdikt na osnovu prikupljenih podataka."""
    malicious = vt_summary.get("malicious", 0) if vt_summary.get("found") else 0
    suspicious = vt_summary.get("suspicious", 0) if vt_summary.get("found") else 0
    abuse_score = abuse_summary.get("abuse_confidence_score", 0) if abuse_summary and abuse_summary.get("found") else 0

    if malicious >= 5 or abuse_score >= 75:
        return "MALICIOUS"
    if malicious >= 1 or suspicious >= 2 or abuse_score >= 25:
        return "SUSPICIOUS"
    if not vt_summary.get("found") and not (abuse_summary and abuse_summary.get("found")):
        return "UNKNOWN"
    return "CLEAN"


VERDICT_COLOR = {
    "MALICIOUS": "bold red",
    "SUSPICIOUS": "bold yellow",
    "CLEAN": "bold green",
    "UNKNOWN": "bold white",
}


def check_ioc(ioc: str, vt_client: VirusTotalClient, abuse_client: AbuseIPDBClient | None) -> dict:
    """Proverava jedan IOC kroz odgovarajuće API-je i vraća strukturiran rezultat."""
    ioc_type = detect_ioc_type(ioc)
    result = {
        "ioc": ioc,
        "type": ioc_type,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "virustotal": {"found": False},
        "abuseipdb": None,
        "verdict": "UNKNOWN",
        "error": None,
    }

    if ioc_type == IOCType.UNKNOWN:
        result["error"] = "Nije prepoznat format (nije validan IP, domen ili hash)."
        return result

    # VirusTotal provera (za sve tipove)
    try:
        if ioc_type == IOCType.IP:
            raw_vt = vt_client.check_ip(ioc)
        elif ioc_type == IOCType.DOMAIN:
            raw_vt = vt_client.check_domain(ioc)
        else:  # HASH
            raw_vt = vt_client.check_hash(ioc)
        result["virustotal"] = VirusTotalClient.summarize(raw_vt)
    except VirusTotalError as e:
        result["error"] = f"VirusTotal: {e}"

    # AbuseIPDB provera (samo za IP adrese)
    if ioc_type == IOCType.IP and abuse_client:
        try:
            raw_abuse = abuse_client.check_ip(ioc)
            result["abuseipdb"] = AbuseIPDBClient.summarize(raw_abuse)
        except AbuseIPDBError as e:
            prev = result["error"]
            result["error"] = f"{prev} | AbuseIPDB: {e}" if prev else f"AbuseIPDB: {e}"

    result["verdict"] = get_verdict(result["virustotal"], result["abuseipdb"])
    return result


def print_report(result: dict):
    """Ispisuje rezultat u terminal koristeći rich formatting."""
    verdict = result["verdict"]
    color = VERDICT_COLOR.get(verdict, "white")

    title = f"[{color}]{result['ioc']}  —  {verdict}[/{color}]  ({result['type'].upper()})"
    console.print(Panel(title, expand=False))

    if result["error"]:
        console.print(f"[dim]Napomena: {result['error']}[/dim]")

    vt = result["virustotal"]
    if vt.get("found"):
        table = Table(title="VirusTotal", show_header=True, header_style="bold cyan")
        table.add_column("Polje")
        table.add_column("Vrednost")
        table.add_row("Malicious", str(vt.get("malicious")))
        table.add_row("Suspicious", str(vt.get("suspicious")))
        table.add_row("Harmless", str(vt.get("harmless")))
        table.add_row("Undetected", str(vt.get("undetected")))
        if vt.get("country"):
            table.add_row("Country", str(vt.get("country")))
        if vt.get("as_owner"):
            table.add_row("AS Owner", str(vt.get("as_owner")))
        if vt.get("categories"):
            table.add_row("Categories", str(vt.get("categories")))
        if vt.get("type_description"):
            table.add_row("File type", str(vt.get("type_description")))
        if vt.get("meaningful_name"):
            table.add_row("File name", str(vt.get("meaningful_name")))
        console.print(table)
    else:
        console.print("[dim]VirusTotal: nema podataka (nije pronađeno).[/dim]")

    abuse = result["abuseipdb"]
    if abuse:
        if abuse.get("found"):
            table = Table(title="AbuseIPDB", show_header=True, header_style="bold magenta")
            table.add_column("Polje")
            table.add_column("Vrednost")
            table.add_row("Abuse Confidence Score", f"{abuse.get('abuse_confidence_score')}%")
            table.add_row("Total Reports", str(abuse.get("total_reports")))
            table.add_row("Distinct Reporters", str(abuse.get("num_distinct_users")))
            table.add_row("Country", str(abuse.get("country_code")))
            table.add_row("ISP", str(abuse.get("isp")))
            table.add_row("Usage Type", str(abuse.get("usage_type")))
            table.add_row("Tor Exit Node", str(abuse.get("is_tor")))
            table.add_row("Whitelisted", str(abuse.get("is_whitelisted")))
            console.print(table)
        else:
            console.print("[dim]AbuseIPDB: nema podataka.[/dim]")

    console.print()


def export_json(results: list[dict], path: str):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)


def export_markdown(results: list[dict], path: str):
    lines = ["# IOC Checker Report", ""]
    lines.append(f"Generisano: {datetime.now(timezone.utc).isoformat()}")
    lines.append("")
    lines.append("| IOC | Tip | Verdikt | VT Malicious | Abuse Score | Napomena |")
    lines.append("|---|---|---|---|---|---|")
    for r in results:
        vt = r["virustotal"]
        abuse = r["abuseipdb"]
        vt_mal = vt.get("malicious", "-") if vt.get("found") else "-"
        abuse_score = f"{abuse.get('abuse_confidence_score')}%" if abuse and abuse.get("found") else "-"
        note = (r["error"] or "").replace("|", "/")
        lines.append(f"| {r['ioc']} | {r['type']} | {r['verdict']} | {vt_mal} | {abuse_score} | {note} |")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def main():
    parser = argparse.ArgumentParser(
        description="IOC Checker — proverava IP/domain/hash kroz VirusTotal i AbuseIPDB."
    )
    parser.add_argument("ioc", nargs="?", help="Jedan IOC za proveru (IP, domen ili hash).")
    parser.add_argument("--file", "-f", help="Fajl sa listom IOC-a, jedan po liniji.")
    parser.add_argument("--output", "-o", help="Putanja za export report-a (json ili md).")
    parser.add_argument(
        "--format", choices=["json", "markdown"], default="json",
        help="Format za export (podrazumevano: json)."
    )
    args = parser.parse_args()

    if not args.ioc and not args.file:
        parser.print_help()
        sys.exit(1)

    load_dotenv()
    vt_key = os.getenv("VT_API_KEY")
    abuse_key = os.getenv("ABUSEIPDB_API_KEY")

    try:
        vt_client = VirusTotalClient(vt_key)
    except VirusTotalError as e:
        console.print(f"[bold red]Greška:[/bold red] {e}")
        sys.exit(1)

    abuse_client = None
    if abuse_key:
        abuse_client = AbuseIPDBClient(abuse_key)
    else:
        console.print("[dim]Napomena: ABUSEIPDB_API_KEY nije postavljen — AbuseIPDB provera će biti preskočena.[/dim]\n")

    iocs = [args.ioc] if args.ioc else read_iocs_from_file(args.file)

    results = []
    for i, ioc in enumerate(iocs):
        result = check_ioc(ioc, vt_client, abuse_client)
        results.append(result)
        print_report(result)

        # Poštovanje VT free-tier rate limita kada ima još IOC-a na redu
        if i < len(iocs) - 1:
            time.sleep(VT_RATE_LIMIT_DELAY)

    if args.output:
        if args.format == "json":
            export_json(results, args.output)
        else:
            export_markdown(results, args.output)
        console.print(f"[bold green]Report sačuvan:[/bold green] {args.output}")


if __name__ == "__main__":
    main()
