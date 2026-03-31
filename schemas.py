"""
Domain models and API response schemas.

Author: Mohammad Khan
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Annotated

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class Protocol(str, Enum):
    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"
    OTHER = "OTHER"


class AlertSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    WARNING = "WARNING"
    INFO = "INFO"


class AlertKind(str, Enum):
    PORT_SCAN = "port_scan"
    SYN_FLOOD = "syn_flood"
    UDP_SPIKE = "udp_spike"
    NEW_DEVICE = "new_device"


# ---------------------------------------------------------------------------
# Internal domain objects
# ---------------------------------------------------------------------------

class PacketRecord(BaseModel):
    """A single captured or simulated packet."""
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    src_ip: str
    dst_ip: str
    protocol: Protocol
    src_port: int | None = None
    dst_port: int | None = None
    size_bytes: int = 0
    flags: str = ""          # e.g. "S" for SYN, "SA" for SYN-ACK


class Alert(BaseModel):
    """A detected network anomaly."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    severity: AlertSeverity
    kind: AlertKind
    title: str
    detail: str
    source_ip: str
    resolved: bool = False


# ---------------------------------------------------------------------------
# API response schemas
# ---------------------------------------------------------------------------

class TrafficSnapshot(BaseModel):
    """One second of aggregated traffic data."""
    timestamp: datetime
    packets_per_sec: int
    bytes_per_sec: int
    tcp: int
    udp: int
    icmp: int
    other: int


class ProtocolBreakdown(BaseModel):
    tcp_pct: Annotated[float, Field(ge=0, le=100)]
    udp_pct: Annotated[float, Field(ge=0, le=100)]
    icmp_pct: Annotated[float, Field(ge=0, le=100)]
    other_pct: Annotated[float, Field(ge=0, le=100)]


class TopTalker(BaseModel):
    ip: str
    packets: int
    bytes: int
    protocol: Protocol
    flagged: bool


class SystemStats(BaseModel):
    packets_per_sec: int
    active_alerts: int
    flagged_ips: int
    uptime_seconds: float


class TrafficResponse(BaseModel):
    history: list[TrafficSnapshot]
    current: TrafficSnapshot | None


class AlertsResponse(BaseModel):
    alerts: list[Alert]
    total: int


class TopTalkersResponse(BaseModel):
    talkers: list[TopTalker]


class StatsResponse(BaseModel):
    stats: SystemStats
    protocol_breakdown: ProtocolBreakdown
