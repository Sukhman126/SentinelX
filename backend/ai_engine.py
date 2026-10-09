"""
AI Security Assistant.

Design goal: the platform must be fully demo-able with zero API keys,
but upgrade automatically to a real LLM the moment OPENAI_API_KEY is set.

- If OPENAI_API_KEY is present -> calls OpenAI's chat completions API.
- Otherwise -> falls back to a deterministic, template-based "expert
  system" that still produces genuinely useful, CVE-aware explanations
  using the local CVE database + risk engine. This keeps every AI
  feature in the spec (explain CVE, summarize report, generate exec
  summary, business-language translation) working out of the box.
"""

import os
from typing import Optional
from cve_data import get_cve_details

OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY")


def _call_openai(prompt: str, system: str = "You are a senior application security consultant.") -> str:
    import requests
    resp = requests.post(
        "https://api.openai.com/v1/chat/completions",
        headers={"Authorization": f"Bearer {OPENAI_API_KEY}", "Content-Type": "application/json"},
        json={
            "model": "gpt-4o-mini",
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.3,
        },
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json()["choices"][0]["message"]["content"]


def explain_cve(cve_id: Optional[str], vulnerability_title: Optional[str], context: Optional[str]) -> str:
    details = get_cve_details(cve_id) if cve_id else None

    if OPENAI_API_KEY:
        prompt = (
            f"Explain vulnerability {cve_id or vulnerability_title} for a penetration "
            f"test report. Context: {context or 'N/A'}. Cover: what it is, risk, "
            f"business impact, technical details, remediation steps, and best practices. "
            f"Be concise and use clear headings."
        )
        return _call_openai(prompt)

    # --- Offline template-based fallback ---
    if details:
        return (
            f"## {details['cve_id']} - {details['title']}\n\n"
            f"**What it is:** {details['description']}\n\n"
            f"**Risk (CVSS {details['cvss_score']} / {details['severity']}):** "
            f"This is classified as {details['severity']} severity, exploitable over "
            f"{details['attack_vector']}. Attackers who can reach the vulnerable "
            f"service can leverage this weakness without needing prior access to the host.\n\n"
            f"**Business Impact:** Depending on the exposed asset, exploitation could "
            f"lead to unauthorized data access, service disruption, or full host "
            f"compromise -- with downstream risk to any systems that trust this host.\n\n"
            f"**Technical Details:** {details['description']}\n\n"
            f"**Remediation:** {details['remediation']}\n\n"
            f"**Best Practices:** Maintain a regular patch cadence, restrict "
            f"management/service ports to trusted networks, and monitor for "
            f"exploitation attempts via IDS/IPS signatures for this CVE."
        )

    title = vulnerability_title or cve_id or "this finding"
    return (
        f"## {title}\n\n"
        f"No entry for this identifier exists in the local CVE knowledge base yet "
        f"(this demo ships a curated subset). In a production deployment this would "
        f"be resolved live against the NVD API.\n\n"
        f"**General guidance:** Verify the finding manually, check the vendor "
        f"advisory for the affected product/version, confirm exploitability in your "
        f"environment, and prioritize remediation based on exposure (internet-facing "
        f"services should be patched first) and the sensitivity of the affected asset."
    )


def summarize_findings(findings_text: str, executive: bool = False) -> str:
    """Summarizes a batch of findings, either technically or for an executive audience."""
    if OPENAI_API_KEY:
        audience = "a non-technical executive audience" if executive else "a technical security team"
        prompt = (
            f"Summarize the following vulnerability findings for {audience}. "
            f"Be concise, group by severity, and highlight the top 3 risks:\n\n{findings_text}"
        )
        return _call_openai(prompt)

    # Offline fallback: simple structured summary
    lines = [l for l in findings_text.split("\n") if l.strip()]
    total = len(lines)
    if executive:
        return (
            f"This assessment identified {total} findings across the tested scope. "
            f"Critical and high-severity issues represent the greatest business risk "
            f"and should be remediated first, particularly on internet-facing systems. "
            f"Overall security posture should be re-evaluated after remediation and "
            f"validated with a follow-up assessment."
        )
    return (
        f"{total} findings recorded. Review the vulnerability dashboard for full "
        f"per-host detail; prioritize items with the highest composite risk score, "
        f"which factors in CVSS, known exploit availability, and exposure."
    )
