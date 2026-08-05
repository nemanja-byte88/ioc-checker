"""
utils.py
Detekcija tipa IOC-a (Indicator of Compromise) na osnovu regex patterna.
Podržani tipovi: IPv4, domain, MD5, SHA1, SHA256.
"""

import re

IPV4_PATTERN = re.compile(
    r"^(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])"
    r"(\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3}$"
)

DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)

MD5_PATTERN = re.compile(r"^[a-fA-F0-9]{32}$")
SHA1_PATTERN = re.compile(r"^[a-fA-F0-9]{40}$")
SHA256_PATTERN = re.compile(r"^[a-fA-F0-9]{64}$")


class IOCType:
    IP = "ip"
    DOMAIN = "domain"
    HASH = "hash"
    UNKNOWN = "unknown"


def detect_ioc_type(value: str) -> str:
    """Vraća tip IOC-a na osnovu formata ulaznog stringa."""
    value = value.strip()

    if IPV4_PATTERN.match(value):
        return IOCType.IP

    if MD5_PATTERN.match(value) or SHA1_PATTERN.match(value) or SHA256_PATTERN.match(value):
        return IOCType.HASH

    # Domain provera ide poslednja jer hash i IP takođe mogu sadržati tačke/brojeve
    if DOMAIN_PATTERN.match(value) and not value.replace(".", "").isdigit():
        return IOCType.DOMAIN

    return IOCType.UNKNOWN


def read_iocs_from_file(filepath: str) -> list[str]:
    """Učitava IOC-e iz fajla, jedan po liniji. Ignoriše prazne linije i komentare (#)."""
    iocs = []
    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                iocs.append(line)
    return iocs
