from pydantic import BaseModel, EmailStr
from typing import Optional, List
import datetime


# ---------- Auth ----------
class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str


class UserOut(BaseModel):
    id: int
    username: str
    email: str
    role: str

    class Config:
        from_attributes = True


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


# ---------- Projects ----------
class ProjectCreate(BaseModel):
    name: str
    client_name: Optional[str] = None
    description: Optional[str] = None


class ProjectOut(BaseModel):
    id: int
    name: str
    client_name: Optional[str]
    description: Optional[str]
    created_at: datetime.datetime

    class Config:
        from_attributes = True


# ---------- Vulnerabilities ----------
class VulnerabilityOut(BaseModel):
    id: int
    host_id: int
    title: str
    cve_id: Optional[str]
    description: Optional[str]
    severity: str
    cvss_score: float
    risk_score: float
    remediation: Optional[str]
    port: Optional[int]
    status: str

    class Config:
        from_attributes = True


class VulnerabilityUpdate(BaseModel):
    status: Optional[str] = None
    business_impact: Optional[int] = None
    internet_exposed: Optional[bool] = None


# ---------- Hosts ----------
class PortOut(BaseModel):
    port_number: int
    protocol: str
    service: Optional[str]
    product: Optional[str]
    version: Optional[str]
    state: str

    class Config:
        from_attributes = True


class HostOut(BaseModel):
    id: int
    ip_address: str
    hostname: Optional[str]
    os_name: Optional[str]
    status: str
    ports: List[PortOut] = []
    vulnerabilities: List[VulnerabilityOut] = []

    class Config:
        from_attributes = True


# ---------- AI ----------
class AIExplainRequest(BaseModel):
    cve_id: Optional[str] = None
    vulnerability_title: Optional[str] = None
    context: Optional[str] = None


class AISummaryRequest(BaseModel):
    project_id: int
