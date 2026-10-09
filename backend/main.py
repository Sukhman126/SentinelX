import os
import datetime
from typing import List, Optional

from fastapi import FastAPI, Depends, HTTPException, UploadFile, File, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

import models
import schemas
from database import engine, get_db, Base
from security import (
    hash_password, verify_password, create_access_token, get_current_user,
)
from parser import parse_nmap_xml, parse_json_findings, parse_csv_findings
from risk import score_finding, summarize_by_severity
from ai_engine import explain_cve, summarize_findings
from report_generator import generate_pdf_report

Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="SentinelX API",
    description="AI-Powered Vulnerability Assessment & Security Intelligence Platform",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tighten to your frontend origin in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

REPORTS_DIR = os.path.join(os.path.dirname(__file__), "..", "generated_reports")
os.makedirs(REPORTS_DIR, exist_ok=True)


# =========================================================
# AUTH
# =========================================================
@app.post("/auth/register", response_model=schemas.UserOut, status_code=201)
def register(payload: schemas.UserCreate, db: Session = Depends(get_db)):
    if db.query(models.User).filter(models.User.username == payload.username).first():
        raise HTTPException(400, "Username already taken")
    if db.query(models.User).filter(models.User.email == payload.email).first():
        raise HTTPException(400, "Email already registered")

    # first registered user becomes admin
    is_first_user = db.query(models.User).count() == 0
    user = models.User(
        username=payload.username,
        email=payload.email,
        hashed_password=hash_password(payload.password),
        role="admin" if is_first_user else "user",
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@app.post("/auth/login", response_model=schemas.Token)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(401, "Incorrect username or password")
    token = create_access_token({"sub": user.username, "role": user.role})
    return {"access_token": token, "token_type": "bearer"}


@app.get("/auth/me", response_model=schemas.UserOut)
def me(user: models.User = Depends(get_current_user)):
    return user


# =========================================================
# PROJECTS
# =========================================================
@app.post("/projects", response_model=schemas.ProjectOut, status_code=201)
def create_project(payload: schemas.ProjectCreate, db: Session = Depends(get_db),
                    user: models.User = Depends(get_current_user)):
    project = models.Project(
        name=payload.name, client_name=payload.client_name,
        description=payload.description, owner_id=user.id,
    )
    db.add(project)
    db.commit()
    db.refresh(project)
    return project


@app.get("/projects", response_model=List[schemas.ProjectOut])
def list_projects(db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    return db.query(models.Project).filter(models.Project.owner_id == user.id).all()


def _get_owned_project(project_id: int, db: Session, user: models.User) -> models.Project:
    project = db.query(models.Project).filter(
        models.Project.id == project_id, models.Project.owner_id == user.id
    ).first()
    if not project:
        raise HTTPException(404, "Project not found")
    return project


@app.get("/projects/{project_id}", response_model=schemas.ProjectOut)
def get_project(project_id: int, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    return _get_owned_project(project_id, db, user)


@app.delete("/projects/{project_id}", status_code=204)
def delete_project(project_id: int, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    project = _get_owned_project(project_id, db, user)
    db.delete(project)
    db.commit()
    return None


# =========================================================
# REPORT IMPORT
# =========================================================
@app.post("/projects/{project_id}/import")
async def import_scan_report(
    project_id: int,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    project = _get_owned_project(project_id, db, user)
    content = await file.read()
    filename = file.filename or "upload"

    ext = filename.lower().rsplit(".", 1)[-1] if "." in filename else ""
    try:
        if ext == "xml":
            parsed_hosts = parse_nmap_xml(content)
            source_type = "nmap_xml"
        elif ext == "json":
            parsed_hosts = parse_json_findings(content)
            source_type = "json"
        elif ext == "csv":
            parsed_hosts = parse_csv_findings(content)
            source_type = "csv"
        else:
            raise HTTPException(400, f"Unsupported file type: .{ext}. Supported: .xml (Nmap), .json, .csv")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(400, f"Failed to parse file: {e}")

    host_count = 0
    vuln_count = 0

    for h in parsed_hosts:
        host = models.Host(
            project_id=project.id,
            ip_address=h["ip_address"],
            hostname=h.get("hostname"),
            os_name=h.get("os_name"),
            status=h.get("status", "up"),
        )
        db.add(host)
        db.flush()  # get host.id
        host_count += 1

        for p in h.get("ports", []):
            db.add(models.Port(
                host_id=host.id, port_number=p["port_number"], protocol=p.get("protocol", "tcp"),
                service=p.get("service"), product=p.get("product"), version=p.get("version"),
                state=p.get("state", "open"),
            ))

        for finding in h.get("vulnerabilities", []):
            scored = score_finding(dict(finding))
            db.add(models.Vulnerability(
                host_id=host.id,
                project_id=project.id,
                title=scored["title"],
                cve_id=scored.get("cve_id"),
                description=scored.get("description"),
                severity=scored["severity"],
                cvss_score=scored.get("cvss_score", 0.0),
                attack_vector=scored.get("attack_vector"),
                exploit_available=scored.get("exploit_available", False),
                internet_exposed=scored.get("internet_exposed", False),
                risk_score=scored["risk_score"],
                remediation=scored.get("remediation"),
                port=scored.get("port"),
            ))
            vuln_count += 1

    report = models.ScanReport(
        project_id=project.id, filename=filename, source_type=source_type,
        host_count=host_count, vuln_count=vuln_count,
    )
    db.add(report)
    db.commit()

    return {
        "message": "Import successful",
        "filename": filename,
        "source_type": source_type,
        "hosts_imported": host_count,
        "vulnerabilities_found": vuln_count,
    }


@app.get("/projects/{project_id}/reports")
def list_scan_reports(project_id: int, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    project = _get_owned_project(project_id, db, user)
    reports = db.query(models.ScanReport).filter(models.ScanReport.project_id == project.id).all()
    return [
        {"id": r.id, "filename": r.filename, "source_type": r.source_type,
         "uploaded_at": r.uploaded_at, "host_count": r.host_count, "vuln_count": r.vuln_count}
        for r in reports
    ]


# =========================================================
# ASSET DISCOVERY / HOSTS
# =========================================================
@app.get("/projects/{project_id}/hosts", response_model=List[schemas.HostOut])
def list_hosts(project_id: int, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    project = _get_owned_project(project_id, db, user)
    return db.query(models.Host).filter(models.Host.project_id == project.id).all()


# =========================================================
# VULNERABILITY DASHBOARD
# =========================================================
@app.get("/projects/{project_id}/vulnerabilities", response_model=List[schemas.VulnerabilityOut])
def list_vulnerabilities(
    project_id: int,
    severity: Optional[str] = None,
    status_filter: Optional[str] = None,
    search: Optional[str] = None,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    project = _get_owned_project(project_id, db, user)
    q = db.query(models.Vulnerability).filter(models.Vulnerability.project_id == project.id)
    if severity:
        q = q.filter(models.Vulnerability.severity == severity)
    if status_filter:
        q = q.filter(models.Vulnerability.status == status_filter)
    if search:
        like = f"%{search}%"
        q = q.filter(
            (models.Vulnerability.title.ilike(like)) | (models.Vulnerability.cve_id.ilike(like))
        )
    return q.order_by(models.Vulnerability.risk_score.desc()).all()


@app.patch("/vulnerabilities/{vuln_id}", response_model=schemas.VulnerabilityOut)
def update_vulnerability(
    vuln_id: int, payload: schemas.VulnerabilityUpdate,
    db: Session = Depends(get_db), user: models.User = Depends(get_current_user),
):
    vuln = db.query(models.Vulnerability).join(models.Project).filter(
        models.Vulnerability.id == vuln_id, models.Project.owner_id == user.id
    ).first()
    if not vuln:
        raise HTTPException(404, "Vulnerability not found")

    if payload.status is not None:
        vuln.status = payload.status
    if payload.business_impact is not None:
        vuln.business_impact = payload.business_impact
    if payload.internet_exposed is not None:
        vuln.internet_exposed = payload.internet_exposed

    # recompute risk score after any exposure/impact change
    from risk import compute_risk_score
    vuln.risk_score = compute_risk_score(
        vuln.cvss_score, vuln.exploit_available, vuln.internet_exposed,
        vuln.service_criticality, vuln.business_impact,
    )

    db.commit()
    db.refresh(vuln)
    return vuln


# =========================================================
# EXECUTIVE DASHBOARD
# =========================================================
@app.get("/projects/{project_id}/dashboard")
def executive_dashboard(project_id: int, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    project = _get_owned_project(project_id, db, user)
    hosts = db.query(models.Host).filter(models.Host.project_id == project.id).all()
    vulns = db.query(models.Vulnerability).filter(models.Vulnerability.project_id == project.id).all()

    severity_counts = summarize_by_severity(vulns)
    mean_cvss = round(sum(v.cvss_score for v in vulns) / len(vulns), 2) if vulns else 0.0

    top_risk = sorted(vulns, key=lambda v: v.risk_score, reverse=True)[:5]
    recent_reports = db.query(models.ScanReport).filter(
        models.ScanReport.project_id == project.id
    ).order_by(models.ScanReport.uploaded_at.desc()).limit(5).all()

    # service/port distribution for asset discovery charts
    port_counts = {}
    service_counts = {}
    for h in hosts:
        for p in h.ports:
            port_counts[p.port_number] = port_counts.get(p.port_number, 0) + 1
            if p.service:
                service_counts[p.service] = service_counts.get(p.service, 0) + 1

    return {
        "total_hosts": len(hosts),
        "total_vulnerabilities": len(vulns),
        "critical_findings": severity_counts.get("Critical", 0),
        "mean_cvss": mean_cvss,
        "severity_breakdown": severity_counts,
        "port_distribution": port_counts,
        "service_distribution": service_counts,
        "top_risk_findings": [
            {"id": v.id, "title": v.title, "cve_id": v.cve_id,
             "risk_score": v.risk_score, "severity": v.severity}
            for v in top_risk
        ],
        "recent_reports": [
            {"filename": r.filename, "uploaded_at": r.uploaded_at, "vuln_count": r.vuln_count}
            for r in recent_reports
        ],
    }


# =========================================================
# AI SECURITY ASSISTANT
# =========================================================
@app.post("/ai/explain")
def ai_explain(payload: schemas.AIExplainRequest, user: models.User = Depends(get_current_user)):
    explanation = explain_cve(payload.cve_id, payload.vulnerability_title, payload.context)
    return {"explanation": explanation}


@app.post("/ai/summary")
def ai_project_summary(
    payload: schemas.AISummaryRequest, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)
):
    project = _get_owned_project(payload.project_id, db, user)
    vulns = db.query(models.Vulnerability).filter(models.Vulnerability.project_id == project.id).all()
    findings_text = "\n".join(f"{v.severity} - {v.title} ({v.cve_id or 'N/A'})" for v in vulns) or "No findings."
    return {
        "technical_summary": summarize_findings(findings_text, executive=False),
        "executive_summary": summarize_findings(findings_text, executive=True),
    }


# =========================================================
# REPORT GENERATOR
# =========================================================
@app.post("/projects/{project_id}/generate-report")
def generate_report(project_id: int, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    project = _get_owned_project(project_id, db, user)
    hosts = db.query(models.Host).filter(models.Host.project_id == project.id).all()
    vulns = db.query(models.Vulnerability).filter(models.Vulnerability.project_id == project.id).all()

    timestamp = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    filename = f"SentinelX_Report_{project.id}_{timestamp}.pdf"
    output_path = os.path.join(REPORTS_DIR, filename)

    generate_pdf_report(project, hosts, vulns, output_path)
    return {"message": "Report generated", "filename": filename, "download_url": f"/projects/{project_id}/reports/download/{filename}"}


@app.get("/projects/{project_id}/reports/download/{filename}")
def download_report(project_id: int, filename: str, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    _get_owned_project(project_id, db, user)  # ownership check
    path = os.path.join(REPORTS_DIR, filename)
    if not os.path.isfile(path):
        raise HTTPException(404, "Report not found")
    return FileResponse(path, media_type="application/pdf", filename=filename)


@app.get("/")
def root():
    return {"status": "SentinelX API running", "docs": "/docs"}
