"""
Risk Prioritization Engine.

Composite Risk Score = f(CVSS, Exploit Availability, Internet Exposure,
                          Critical Service Weight, Business Impact)

Score is normalized to a 0-10 scale so it lines up visually with CVSS,
but the components let you separate "how bad is the vulnerability" (CVSS)
from "how bad is it for THIS org" (exposure/business impact/exploit).
"""

from typing import Dict

# Static "exploit available" hints keyed by known CVEs (in a full build
# this would query Exploit-DB / Metasploit modules list).
KNOWN_EXPLOITED = {
    "CVE-2011-2523", "CVE-2017-0144", "CVE-2012-2122",
    "CVE-2021-41773", "CVE-2010-4221",
}

SEVERITY_ORDER = ["Informational", "Low", "Medium", "High", "Critical"]


def cvss_to_severity(cvss: float) -> str:
    if cvss >= 9.0:
        return "Critical"
    if cvss >= 7.0:
        return "High"
    if cvss >= 4.0:
        return "Medium"
    if cvss > 0.0:
        return "Low"
    return "Informational"


def compute_risk_score(
    cvss_score: float,
    exploit_available: bool,
    internet_exposed: bool,
    service_criticality: int = 1,   # 1-5
    business_impact: int = 1,       # 1-5
) -> float:
    """
    Weighted composite score, capped at 10.0:
      - 60% weight: base CVSS (attacker-perspective severity)
      - 15%: exploit availability bonus
      - 10%: internet exposure bonus
      - 10%: service criticality (0-5 scaled to 0-10)
      - 5%:  business impact (0-5 scaled to 0-10)
    """
    cvss_component = cvss_score * 0.60
    exploit_component = (10.0 if exploit_available else 0.0) * 0.15
    exposure_component = (10.0 if internet_exposed else 0.0) * 0.10
    service_component = (service_criticality / 5.0 * 10.0) * 0.10
    impact_component = (business_impact / 5.0 * 10.0) * 0.05

    total = (
        cvss_component + exploit_component + exposure_component
        + service_component + impact_component
    )
    return round(min(total, 10.0), 2)


def score_finding(finding: Dict) -> Dict:
    """Enrich a raw parsed finding dict with exploit flag + computed risk_score."""
    cve_id = finding.get("cve_id")
    exploit_available = cve_id in KNOWN_EXPLOITED if cve_id else False

    # Default heuristics: internet_exposed unknown at import time -> False
    # until the analyst marks the host/finding as externally facing.
    risk_score = compute_risk_score(
        cvss_score=finding.get("cvss_score", 0.0),
        exploit_available=exploit_available,
        internet_exposed=finding.get("internet_exposed", False),
        service_criticality=finding.get("service_criticality", 2),
        business_impact=finding.get("business_impact", 2),
    )

    finding["exploit_available"] = exploit_available
    finding["risk_score"] = risk_score
    if not finding.get("severity"):
        finding["severity"] = cvss_to_severity(finding.get("cvss_score", 0.0))
    return finding


def summarize_by_severity(vulns) -> Dict[str, int]:
    counts = {s: 0 for s in SEVERITY_ORDER}
    for v in vulns:
        sev = v.severity if hasattr(v, "severity") else v.get("severity", "Informational")
        counts[sev] = counts.get(sev, 0) + 1
    return counts
