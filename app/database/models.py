from datetime import datetime, timezone
from typing import Any

from sqlalchemy import Column, DateTime, ForeignKey, Index, Integer, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

class Base(DeclarativeBase):
    pass

class Domain(Base):
    __tablename__ = "domains"
    
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    source: Mapped[str] = mapped_column(String(50))  # e.g., manual, ammas, etc
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    subdomains: Mapped[list["Subdomain"]] = relationship("Subdomain", back_populates="domain", cascade="all, delete-orphan")

class Subdomain(Base):
    __tablename__ = "subdomains"
    
    id: Mapped[int] = mapped_column(primary_key=True)
    domain_id: Mapped[int] = mapped_column(ForeignKey("domains.id"))
    name: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    is_active: Mapped[bool] = mapped_column(default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    domain: Mapped["Domain"] = relationship("Domain", back_populates="subdomains")
    ips: Mapped[list["IPAddress"]] = relationship("IPAddress", back_populates="subdomain", cascade="all, delete-orphan")

class IPAddress(Base):
    __tablename__ = "ips"
    
    id: Mapped[int] = mapped_column(primary_key=True)
    subdomain_id: Mapped[int | None] = mapped_column(ForeignKey("subdomains.id"), nullable=True) # Internal ASM의 경우 Subdomain이 없을 수 있음
    address: Mapped[str] = mapped_column(String(45), index=True, unique=True)  # IPv4 or IPv6, 중복 삽입 방지
    is_internal: Mapped[bool] = mapped_column(default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    subdomain: Mapped["Subdomain"] = relationship("Subdomain", back_populates="ips")
    ports: Mapped[list["Port"]] = relationship("Port", back_populates="ip_address", cascade="all, delete-orphan")

class Port(Base):
    __tablename__ = "ports"
    
    id: Mapped[int] = mapped_column(primary_key=True)
    ip_id: Mapped[int] = mapped_column(ForeignKey("ips.id"))
    port_number: Mapped[int] = mapped_column(Integer)
    protocol: Mapped[str] = mapped_column(String(10), default="tcp")
    service_name: Mapped[str | None] = mapped_column(String(100), nullable=True)
    service_version: Mapped[str | None] = mapped_column(String(100), nullable=True)
    # httpx/Nmap 등에서 넘어오는 부가적인 웹 기술 데이터나 배너 정보를 유연하게 저장
    metadata_info: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    ip_address: Mapped["IPAddress"] = relationship("IPAddress", back_populates="ports")
    vulnerabilities: Mapped[list["Vulnerability"]] = relationship("Vulnerability", back_populates="port", cascade="all, delete-orphan")

class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    
    id: Mapped[int] = mapped_column(primary_key=True)
    port_id: Mapped[int | None] = mapped_column(ForeignKey("ports.id"), nullable=True)
    tool_name: Mapped[str] = mapped_column(String(50)) # nuclei, etc
    vuln_name: Mapped[str] = mapped_column(String(255))
    severity: Mapped[str] = mapped_column(String(50))
    description: Mapped[str | None] = mapped_column(String, nullable=True)
    # Nuclei 결과 원본 JSON 전체를 저장하여 정보 소실 방지
    raw_data: Mapped[dict[str, Any]] = mapped_column(JSONB)
    discovered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    port: Mapped["Port"] = relationship("Port", back_populates="vulnerabilities")

# 특정 IP에 특정 포트가 2개 생기지 않도록 고유 인덱스 제약 조건
Index("ix_ports_ip_port", Port.ip_id, Port.port_number, Port.protocol, unique=True)
