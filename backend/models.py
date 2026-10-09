import datetime
from sqlalchemy import (
    Column, Integer, String, Float, DateTime, ForeignKey, Text, Boolean
)
from sqlalchemy.orm import relationship
from database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(80), unique=True, index=True, nullable=False)
    email = Column(String(120), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    role = Column(String(20), default="user")  # "admin" or "user"
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    projects = relationship("Project", back_populates="owner")


class Project(Base):
    __tablename__ = "projects"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(150), nullable=False)
    client_name = Column(String(150), nullable=True)
    description = Column(Text, nullable=True)
    owner_id = Column(Integer, ForeignKey("users.id"))
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    owner = relationship("User", back_populates="projects")
    hosts = relationship("Host", back_populates="project", cascade="all, delete-orphan")
    reports = relationship("ScanReport", back_populates="project", cascade="all, delete-orphan")


class ScanReport(Base):
    """Represents one uploaded/imported scan file (Nmap XML, Nessus, JSON, CSV)."""
    __tablename__ = "scan_reports"

    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("projects.id"))
    filename = Column(String(255), nullable=False)
    source_type = Column(String(30), nullable=False)  # nmap_xml, nessus, json, csv
    uploaded_at = Column(DateTime, default=datetime.datetime.utcnow)
    host_count = Column(Integer, default=0)
    vuln_count = Column(Integer, default=0)

    project = relationship("Project", back_populates="reports")


class Host(Base):
    __tablename__ = "hosts"

    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("projects.id"))
    ip_address = Column(String(45), nullable=False)
    hostname = Column(String(255), nullable=True)
    os_name = Column(String(255), nullable=True)
    status = Column(String(20), default="up")
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    project = relationship("Project", back_populates="hosts")
    ports = relationship("Port", back_populates="host", cascade="all, delete-orphan")
    vulnerabilities = relationship("Vulnerability", back_populates="host", cascade="all, delete-orphan")


class Port(Base):
    __tablename__ = "ports"

    id = Column(Integer, primary_key=True, index=True)
    host_id = Column(Integer, ForeignKey("hosts.id"))
    port_number = Column(Integer, nullable=False)
    protocol = Column(String(10), default="tcp")
    service = Column(String(100), nullable=True)
    product = Column(String(150), nullable=True)
    version = Column(String(100), nullable=True)
    state = Column(String(20), default="open")

    host = relationship("Host", back_populates="ports")


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True, index=True)
    host_id = Column(Integer, ForeignKey("hosts.id"))
    project_id = Column(Integer, ForeignKey("projects.id"))

    title = Column(String(255), nullable=False)
    cve_id = Column(String(30), nullable=True, index=True)
    description = Column(Text, nullable=True)
    severity = Column(String(20), default="Informational")  # Critical/High/Medium/Low/Informational
    cvss_score = Column(Float, default=0.0)
    attack_vector = Column(String(50), nullable=True)
    exploit_available = Column(Boolean, default=False)
    internet_exposed = Column(Boolean, default=False)
    service_criticality = Column(Integer, default=1)  # 1-5 weight
    business_impact = Column(Integer, default=1)  # 1-5 weight
    risk_score = Column(Float, default=0.0)  # computed composite score
    remediation = Column(Text, nullable=True)
    port = Column(Integer, nullable=True)
    status = Column(String(20), default="open")  # open/mitigated/accepted/false_positive
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    host = relationship("Host", back_populates="vulnerabilities")
