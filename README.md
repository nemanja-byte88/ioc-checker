# IOC Checker

CLI alat za brzu proveru **Indicators of Compromise** (IP adrese, domeni, fajl hash-evi) kroz **VirusTotal** i **AbuseIPDB** API. Namenjen SOC/threat-intel workflow-u — daš mu IOC (ili listu), a on vrati strukturiran report sa verdiktom (`CLEAN` / `SUSPICIOUS` / `MALICIOUS` / `UNKNOWN`).

## Šta radi

- Automatski prepoznaje tip IOC-a: IPv4, domen, ili hash (MD5 / SHA1 / SHA256)
- Proverava IP/domen/hash kroz **VirusTotal API v3**
- Za IP adrese dodatno proverava **AbuseIPDB** (abuse confidence score, broj prijava, ISP, Tor exit node...)
- Kombinuje rezultate u jednostavan verdikt po heuristici
- Ispisuje čitljiv report u terminalu (uz `rich` biblioteku)
- Podržava batch proveru iz fajla (lista IOC-a, jedan po liniji)
- Export report-a u **JSON** ili **Markdown**
- Poštuje VirusTotal free-tier rate limit (4 zahteva/min)

## Instalacija

```bash
git clone https://github.com/<tvoj-username>/ioc-checker.git
cd ioc-checker
pip install -r requirements.txt
```

Napravi `.env` fajl (na osnovu `.env.example`):

```bash
cp .env.example .env
```

Upiši svoje API ključeve u `.env`:

- VirusTotal (besplatan): https://www.virustotal.com/gui/my-apikey
- AbuseIPDB (besplatan): https://www.abuseipdb.com/account/api

> AbuseIPDB ključ je opcionalan — ako ga nema, alat i dalje radi, samo preskače tu proveru (relevantno samo za IP adrese).

## Upotreba

Provera jednog IOC-a:

```bash
python ioc_checker.py 8.8.8.8
python ioc_checker.py evil-domain.com
python ioc_checker.py 44d88612fea8a8f36de82e1278abb02f
```

Batch provera iz fajla:

```bash
python ioc_checker.py --file iocs_sample.txt
```

Export u JSON ili Markdown:

```bash
python ioc_checker.py --file iocs_sample.txt --output report.json
python ioc_checker.py --file iocs_sample.txt --output report.md --format markdown
```

## Primer izlaza (terminal)

```
╭──────────────────────────────────────╮
│ 8.8.8.8  —  CLEAN  (IP)               │
╰──────────────────────────────────────╯

  VirusTotal
  ┌────────────┬─────────┐
  │ Malicious  │ 0       │
  │ Suspicious │ 0       │
  │ Harmless   │ 82      │
  │ Country    │ US      │
  │ AS Owner   │ GOOGLE  │
  └────────────┴─────────┘

  AbuseIPDB
  ┌─────────────────────────┬─────┐
  │ Abuse Confidence Score  │ 0%  │
  │ Total Reports           │ 0   │
  │ ISP                     │ ... │
  └─────────────────────────┴─────┘
```

## Struktura projekta

```
ioc-checker/
├── ioc_checker.py         # CLI entry point, orkestracija i report generisanje
├── utils.py                # Detekcija tipa IOC-a (regex)
├── clients/
│   ├── virustotal.py       # VirusTotal API v3 klijent
│   └── abuseipdb.py        # AbuseIPDB API klijent
├── requirements.txt
├── .env.example
└── iocs_sample.txt         # Primer liste za batch mode
```

## Verdikt heuristika

| Uslov | Verdikt |
|---|---|
| VT malicious ≥ 5 ili AbuseIPDB score ≥ 75 | **MALICIOUS** |
| VT malicious ≥ 1, suspicious ≥ 2, ili AbuseIPDB score ≥ 25 | **SUSPICIOUS** |
| Nema podataka ni na jednom servisu | **UNKNOWN** |
| Ostalo | **CLEAN** |

Ovo je namerno jednostavna heuristika (edukativni/portfolio projekat) — u produkcionom SOC okruženju verdikt bi zavisio i od konteksta (npr. internih threat-intel feed-ova, MITRE ATT&CK mapiranja, itd).

## Napomene

- VirusTotal free tier ima limit od 4 zahteva/min — alat automatski čeka između poziva kod batch provere.
- `.env` fajl sadrži tajne ključeve i ne treba ga commit-ovati (već je u `.gitignore`).

## Moguća proširenja

- IPv6 podrška
- Integracija sa dodatnim izvorima (Shodan, GreyNoise, OTX AlienVault)
- Slack/Discord webhook notifikacije za MALICIOUS nalaze
- CSV export
- Web dashboard (Flask/FastAPI)
