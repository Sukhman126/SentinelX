"""
CVE Intelligence Module.

Maps a product + version fingerprint (as reported by Nmap service
detection) to known CVEs. Ships with a small curated dataset covering
common lab/CTF-style services so the platform works fully offline and
demonstrates the CVE-mapping/CVSS/remediation workflow end-to-end.

To go further: swap `lookup_cve()`'s body for a call to the NVD REST API
(https://services.nvd.nist.gov/rest/json/cves/2.0) keyed by CPE, and
cache results in the `cve_cache` table. The rest of the platform
(risk engine, dashboard, report generator) is written against this
same return shape, so no other code needs to change.
"""

from typing import List, Dict, Optional

# Curated fingerprint -> CVE dataset (subset, for demo/lab purposes)
_CVE_DB = [
    {
        "product": "openssh", "version_prefix": "7.",
        "cve_id": "CVE-2018-15473", "title": "OpenSSH User Enumeration",
        "description": "OpenSSH through 7.7 allows remote attackers to enumerate valid "
                        "usernames via a crafted authentication request due to timing "
                        "differences and error responses.",
        "severity": "Medium", "cvss_score": 5.3, "attack_vector": "Network",
        "remediation": "Upgrade OpenSSH to 7.8 or later.",
    },
    {
        "product": "openssh", "version_prefix": "6.",
        "cve_id": "CVE-2016-6210", "title": "OpenSSH Username Enumeration via Timing",
        "description": "Observable timing discrepancy in auth-gss2.c in sshd allows "
                        "remote attackers to enumerate users via long password strings.",
        "severity": "Low", "cvss_score": 3.7, "attack_vector": "Network",
        "remediation": "Upgrade OpenSSH to 7.3 or later.",
    },
    {
        "product": "vsftpd", "version_prefix": "2.3.4",
        "cve_id": "CVE-2011-2523", "title": "vsftpd 2.3.4 Backdoor Command Execution",
        "description": "vsftpd 2.3.4 as distributed on several mirrors was modified to "
                        "include a backdoor triggered by a ':)' smiley in the username, "
                        "opening a shell on TCP 6200.",
        "severity": "Critical", "cvss_score": 9.8, "attack_vector": "Network",
        "remediation": "Immediately replace with an official, unmodified vsftpd build "
                        "and verify package checksums.",
    },
    {
        "product": "apache", "version_prefix": "2.4.49",
        "cve_id": "CVE-2021-41773", "title": "Apache HTTP Server Path Traversal & RCE",
        "description": "A path traversal flaw in Apache 2.4.49 allows mapping URLs to "
                        "files outside the document root; if mod_cgi is enabled this "
                        "can lead to remote code execution.",
        "severity": "Critical", "cvss_score": 9.8, "attack_vector": "Network",
        "remediation": "Upgrade to Apache 2.4.51 or later immediately.",
    },
    {
        "product": "apache", "version_prefix": "2.4.",
        "cve_id": "CVE-2022-31813", "title": "Apache mod_proxy X-Forwarded-For Spoofing",
        "description": "mod_proxy in certain Apache HTTP Server configurations fails to "
                        "send the X-Forwarded-For header, allowing IP-based access "
                        "control bypass on backend servers.",
        "severity": "Medium", "cvss_score": 5.3, "attack_vector": "Network",
        "remediation": "Upgrade Apache and review reverse-proxy access-control logic.",
    },
    {
        "product": "mysql", "version_prefix": "5.5",
        "cve_id": "CVE-2012-2122", "title": "MySQL Authentication Bypass",
        "description": "A flaw in MySQL/MariaDB's password comparison allows repeated "
                        "authentication attempts to bypass the password check due to "
                        "improper handling of memcmp() return values.",
        "severity": "Critical", "cvss_score": 9.8, "attack_vector": "Network",
        "remediation": "Upgrade MySQL to a patched release (5.5.24+ / 5.6.6+).",
    },
    {
        "product": "microsoft-ds", "version_prefix": None,
        "cve_id": "CVE-2017-0144", "title": "EternalBlue SMBv1 Remote Code Execution",
        "description": "SMBv1 servers mishandle crafted packets, allowing remote "
                        "attackers to execute arbitrary code (exploited by WannaCry).",
        "severity": "Critical", "cvss_score": 9.3, "attack_vector": "Network",
        "remediation": "Disable SMBv1 entirely and apply MS17-010.",
    },
    {
        "product": "proftpd", "version_prefix": "1.3.3",
        "cve_id": "CVE-2010-4221", "title": "ProFTPD Stack Buffer Overflow",
        "description": "Stack-based buffer overflow in ProFTPD before 1.3.3a via a "
                        "crafted response to a malicious SQL server, when the module "
                        "supporting SQL authentication is used.",
        "severity": "High", "cvss_score": 7.5, "attack_vector": "Network",
        "remediation": "Upgrade to ProFTPD 1.3.3a or later.",
    },
]

# Generic risk info shown for CVE-lookup-by-ID (AI assistant / manual lookups)
# even when not tied to a specific scan finding.
_CVE_INDEX = {c["cve_id"]: c for c in _CVE_DB}


def lookup_cve(product: str, version: Optional[str]) -> List[Dict]:
    """Fingerprint-match a detected product/version against the CVE dataset."""
    if not product:
        return []
    product_l = product.lower()
    matches = []
    for entry in _CVE_DB:
        if entry["product"] not in product_l:
            continue
        if entry["version_prefix"] is None:
            matches.append(entry)
        elif version and version.startswith(entry["version_prefix"]):
            matches.append(entry)
    return matches


def get_cve_details(cve_id: str) -> Optional[Dict]:
    return _CVE_INDEX.get(cve_id.upper())
