"""
API route handlers.

Author: Mohammad Khan
"""

from __future__ import annotations

from fastapi import APIRouter, Query, Request

from app.models.schemas import (
    AlertsResponse,
    ProtocolBreakdown,
    StatsResponse,
    SystemStats,
    TopTalkersResponse,
    TrafficResponse,
)

router = APIRouter()


def _get_collector(request: Request):
    return request.app.state.collector


@router.get("/traffic", response_model=TrafficResponse, summary="Traffic history")
async def get_traffic(request: Request):
    """
    Returns the last 60 seconds of per-second traffic snapshots
    plus the most recent snapshot as `current`.
    """
    collector = _get_collector(request)
    return TrafficResponse(
        history=collector.get_history(),
        current=collector.get_current(),
    )


@router.get("/alerts", response_model=AlertsResponse, summary="Active alerts")
async def get_alerts(
    request: Request,
    limit: int = Query(default=20, ge=1, le=100, description="Max alerts to return"),
):
    """Returns the most recent anomaly alerts, newest first."""
    collector = _get_collector(request)
    alerts = collector.get_alerts()[:limit]
    return AlertsResponse(alerts=alerts, total=len(alerts))


@router.get("/top-talkers", response_model=TopTalkersResponse, summary="Top talkers")
async def get_top_talkers(
    request: Request,
    n: int = Query(default=10, ge=1, le=50, description="Number of IPs to return"),
):
    """Returns the top N source IPs by packet count since startup."""
    collector = _get_collector(request)
    return TopTalkersResponse(talkers=collector.get_top_talkers(n))


@router.get("/stats", response_model=StatsResponse, summary="System stats")
async def get_stats(request: Request):
    """Returns current system metrics and protocol breakdown."""
    collector = _get_collector(request)
    current = collector.get_current()

    pps = current.packets_per_sec if current else 0
    total = max(pps, 1)

    breakdown = ProtocolBreakdown(
        tcp_pct=round((current.tcp / total) * 100, 1) if current else 0,
        udp_pct=round((current.udp / total) * 100, 1) if current else 0,
        icmp_pct=round((current.icmp / total) * 100, 1) if current else 0,
        other_pct=round((current.other / total) * 100, 1) if current else 0,
    )

    alerts = collector.get_alerts()
    active_alerts = sum(1 for a in alerts if not a.resolved)

    return StatsResponse(
        stats=SystemStats(
            packets_per_sec=pps,
            active_alerts=active_alerts,
            flagged_ips=collector.flagged_ip_count,
            uptime_seconds=round(collector.uptime_seconds, 2),
        ),
        protocol_breakdown=breakdown,
    )
