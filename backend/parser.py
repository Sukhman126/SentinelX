"""
Report Import Module.

Parses scan output from common security tools into a normalized
in-memory structure that the rest of the platform (risk engine, CVE
enrichment, dashboard, reports) can consume regardless of the original
tool/format.

Supported today:
  - Nmap XML   (nmap -oX)
  - Generic JSON (custom / already-normalized findings)
  - CSV        (host,port,service,version,cve_id,severity,description)

Nessus (.nessus, which is itself XML with a different schema) can be
added the same way -- see parse_nessus_xml() stub below for the shape
to follow.
"""

import csv
import io
import json
import xml.etree.ElementTree as ET
from typing import List, Dict, Any

from cve_data import lookup_cve


def parse_nmap_xml(xml_bytes: bytes) -> List[Dict[str, Any]]:
    """
    Parses an Nmap XML report (nmap -oX output.xml) into a list of
    normalized host dicts:

    {
        "ip_address": "10.0.0.5",
        "hostname": "web01.lab",
        "os_name": "Linux 5.x",
        "status": "up",
        "ports": [{"port_number":22,"protocol":"tcp","service":"ssh",
                    "product":"OpenSSH","version":"8.2p1","state":"open"}],
        "vulnerabilities": [ ... ]   # derived from service/version -> CVE lookup
    }
    """
    root = ET.fromstring(xml_bytes)
    hosts_out = []

    for host_el in root.findall("host"):
        status_el = host_el.find("status")
        status = status_el.get("state") if status_el is not None else "unknown"

        addr_el = host_el.find("address")
        ip_address = addr_el.get("addr") if addr_el is not None else "unknown"

        hostname = None
        hostnames_el = host_el.find("hostnames")
        if hostnames_el is not None:
            hn = hostnames_el.find("hostname")
            if hn is not None:
                hostname = hn.get("name")

        os_name = None
        os_el = host_el.find("os")
        if os_el is not None:
            osmatch = os_el.find("osmatch")
            if osmatch is not None:
                os_name = osmatch.get("name")

        ports = []
        vulnerabilities = []

        ports_el = host_el.find("ports")
        if ports_el is not None:
            for port_el in ports_el.findall("port"):
                port_number = int(port_el.get("portid"))
                protocol = port_el.get("protocol", "tcp")

                state_el = port_el.find("state")
                state = state_el.get("state") if state_el is not None else "unknown"
                if state != "open":
                    continue

                service = product = version = None
                service_el = port_el.find("service")
                if service_el is not None:
                    service = service_el.get("name")
                    product = service_el.get("product")
                    version = service_el.get("version")

                ports.append({
                    "port_number": port_number,
                    "protocol": protocol,
                    "service": service,
                    "product": product,
                    "version": version,
                    "state": state,
                })

                # Attempt CVE enrichment based on product/version fingerprint
                if product:
                    matches = lookup_cve(product, version)
                    for m in matches:
                        vulnerabilities.append({
                            "title": f"{product} {version or ''} - {m['title']}".strip(),
                            "cve_id": m["cve_id"],
                            "description": m["description"],
                            "severity": m["severity"],
                            "cvss_score": m["cvss_score"],
                            "attack_vector": m.get("attack_vector", "Network"),
                            "remediation": m.get("remediation", ""),
                            "port": port_number,
                        })

        hosts_out.append({
            "ip_address": ip_address,
            "hostname": hostname,
            "os_name": os_name,
            "status": status,
            "ports": ports,
            "vulnerabilities": vulnerabilities,
        })

    return hosts_out


def parse_json_findings(json_bytes: bytes) -> List[Dict[str, Any]]:
    """Accepts already-normalized JSON in the same shape parse_nmap_xml() returns,
    OR a flat list of finding dicts, which will be grouped by ip_address."""
    data = json.loads(json_bytes)

    if isinstance(data, list) and data and "ports" in data[0]:
        return data

    # Flat findings -> group by host
    hosts: Dict[str, Dict[str, Any]] = {}
    for row in data:
        ip = row.get("ip_address", "unknown")
        if ip not in hosts:
            hosts[ip] = {
                "ip_address": ip,
                "hostname": row.get("hostname"),
                "os_name": row.get("os_name"),
                "status": "up",
                "ports": [],
                "vulnerabilities": [],
            }
        if row.get("cve_id") or row.get("title"):
            hosts[ip]["vulnerabilities"].append({
                "title": row.get("title", row.get("cve_id", "Unknown finding")),
                "cve_id": row.get("cve_id"),
                "description": row.get("description", ""),
                "severity": row.get("severity", "Medium"),
                "cvss_score": float(row.get("cvss_score", 5.0)),
                "attack_vector": row.get("attack_vector", "Network"),
                "remediation": row.get("remediation", ""),
                "port": row.get("port"),
            })
    return list(hosts.values())


def parse_csv_findings(csv_bytes: bytes) -> List[Dict[str, Any]]:
    """CSV columns expected: ip_address,hostname,port,service,version,cve_id,severity,cvss_score,description"""
    text = csv_bytes.decode("utf-8", errors="ignore")
    reader = csv.DictReader(io.StringIO(text))

    hosts: Dict[str, Dict[str, Any]] = {}
    for row in reader:
        ip = row.get("ip_address", "unknown")
        if ip not in hosts:
            hosts[ip] = {
                "ip_address": ip,
                "hostname": row.get("hostname"),
                "os_name": None,
                "status": "up",
                "ports": [],
                "vulnerabilities": [],
            }
        if row.get("port"):
            hosts[ip]["ports"].append({
                "port_number": int(row["port"]),
                "protocol": "tcp",
                "service": row.get("service"),
                "product": row.get("service"),
                "version": row.get("version"),
                "state": "open",
            })
        if row.get("cve_id") or row.get("severity"):
            hosts[ip]["vulnerabilities"].append({
                "title": row.get("cve_id") or "CSV Import Finding",
                "cve_id": row.get("cve_id"),
                "description": row.get("description", ""),
                "severity": row.get("severity", "Medium"),
                "cvss_score": float(row.get("cvss_score", 5.0) or 5.0),
                "attack_vector": "Network",
                "remediation": "",
                "port": int(row["port"]) if row.get("port") else None,
            })
    return list(hosts.values())


def parse_nessus_xml(xml_bytes: bytes) -> List[Dict[str, Any]]:
    """
    Stub for .nessus file support. The .nessus format is XML with a
    <Report><ReportHost> structure and <ReportItem> findings that already
    include CVE, CVSS, and plugin output -- unlike Nmap it doesn't need
    the CVE-lookup enrichment step. Left as a documented extension point
    so the importer can be wired up the same way as parse_nmap_xml().
    """
    raise NotImplementedError(
        "Nessus import follows the same normalized-host pattern as "
        "parse_nmap_xml(); implement by walking ReportHost/ReportItem "
        "elements and mapping plugin fields (cve, cvss_base_score, "
        "risk_factor, plugin_output) onto the vulnerability dict shape."
    )
