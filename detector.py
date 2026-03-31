"""
Anomaly detection engine.

Stateless detectors receive a snapshot of recent traffic and emit
Alert objects when thresholds are breached. Each detector is a pure
function — easy to unit-test, easy to extend.

Author: Mohammad Khan
"""

from __future__ import annotations

import logging
from collections import defaultdict
from datetime import datetime, timezone

from app.core.config import settings
from app.models.schemas import Alert, AlertKind, AlertSeverity, PacketRecord

logger = logging.getLogger(__name__)


def _now() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Individual detectors
# ---------------------------------------------------------------------------

def detect_port_scan(
    recent_packets: list[PacketRecord],
    known_ips: set[str],
) -> list[Alert]:
    """
    Flag a source IP that touches more than PORT_SCAN_THRESHOLD unique
    destination ports within PORT_SCAN_WINDOW_SECS.
    """
    window = settings.PORT_SCAN_WINDOW_SECS
    threshold = settings.PORT_SCAN_THRESHOLD

    ports_by_src: dict[str, set[int]] = defaultdict(set)

    for pkt in recent_packets:
        if pkt.dst_port is not None:
            ports_by_src[pkt.src_ip].add(pkt.dst_port)

    alerts: list[Alert] = []
    for src_ip, ports in ports_by_src.items():
        if len(ports) >= threshold:
            logger.warning("Port scan detected from %s (%d ports)", src_ip, len(ports))
            alerts.append(
                Alert(
                    severity=AlertSeverity.CRITICAL,
                    kind=AlertKind.PORT_SCAN,
                    title="Port scan detected",
                    detail=f"{len(ports)} unique ports probed in {window}s window",
                    source_ip=src_ip,
                )
            )
    return alerts


def detect_syn_flood(
    recent_packets: list[PacketRecord],
    known_ips: set[str],
) -> list[Alert]:
    """
    Flag a source IP sending SYN packets above SYN_FLOOD_THRESHOLD
    within SYN_FLOOD_WINDOW_SECS without completing handshakes.
    """
    window = settings.SYN_FLOOD_WINDOW_SECS
    threshold = settings.SYN_FLOOD_THRESHOLD

    syn_count: dict[str, int] = defaultdict(int)
    ack_count: dict[str, int] = defaultdict(int)

    for pkt in recent_packets:
        if "S" in pkt.flags and "A" not in pkt.flags:
            syn_count[pkt.src_ip] += 1
        if "A" in pkt.flags:
            ack_count[pkt.src_ip] += 1

    alerts: list[Alert] = []
    for src_ip, count in syn_count.items():
        completion_ratio = ack_count.get(src_ip, 0) / max(count, 1)
        if count >= threshold and completion_ratio < 0.1:
            logger.warning(
                "SYN flood from %s: %d SYNs, %.0f%% completion",
                src_ip, count, completion_ratio * 100,
            )
            alerts.append(
                Alert(
                    severity=AlertSeverity.CRITICAL,
                    kind=AlertKind.SYN_FLOOD,
                    title="SYN flood attempt",
                    detail=f"{count} SYNs with {completion_ratio:.0%} handshake completion",
                    source_ip=src_ip,
                )
            )
    return alerts


def detect_udp_spike(
    recent_packets: list[PacketRecord],
    baseline_udp_rate: float,
) -> list[Alert]:
    """
    Flag a source IP whose UDP packet rate exceeds
    UDP_SPIKE_MULTIPLIER × the rolling baseline.
    """
    multiplier = settings.UDP_SPIKE_MULTIPLIER
    window = settings.UDP_SPIKE_WINDOW_SECS

    udp_by_src: dict[str, int] = defaultdict(int)
    for pkt in recent_packets:
        if pkt.protocol.value == "UDP":
            udp_by_src[pkt.src_ip] += 1

    alerts: list[Alert] = []
    if baseline_udp_rate <= 0:
        return alerts

    for src_ip, count in udp_by_src.items():
        rate = count / window
        if rate > baseline_udp_rate * multiplier:
            logger.warning(
                "UDP spike from %s: %.1f pps vs %.1f baseline",
                src_ip, rate, baseline_udp_rate,
            )
            alerts.append(
                Alert(
                    severity=AlertSeverity.WARNING,
                    kind=AlertKind.UDP_SPIKE,
                    title="Unusual UDP spike",
                    detail=f"{rate:.1f} pps — {rate / baseline_udp_rate:.1f}× above baseline",
                    source_ip=src_ip,
                )
            )
    return alerts


def detect_new_devices(
    recent_packets: list[PacketRecord],
    known_ips: set[str],
) -> tuple[list[Alert], set[str]]:
    """
    Emit an INFO alert for any source IP not previously seen.
    Returns both the alerts and the updated known-IP set.
    """
    seen = {pkt.src_ip for pkt in recent_packets}
    new_ips = seen - known_ips

    alerts = [
        Alert(
            severity=AlertSeverity.INFO,
            kind=AlertKind.NEW_DEVICE,
            title="New device joined",
            detail=f"First packet observed from {ip}",
            source_ip=ip,
        )
        for ip in new_ips
    ]

    return alerts, known_ips | new_ips


# ---------------------------------------------------------------------------
# Aggregated runner
# ---------------------------------------------------------------------------

class AnomalyDetector:
    """
    Runs all detectors against a window of recent packets
    and returns deduplicated alerts.
    """

    def __init__(self) -> None:
        self._known_ips: set[str] = set()
        self._seen_alert_keys: set[tuple[str, str]] = set()

    def run(
        self,
        recent_packets: list[PacketRecord],
        baseline_udp_rate: float = 0.0,
    ) -> list[Alert]:
        alerts: list[Alert] = []

        alerts += detect_port_scan(recent_packets, self._known_ips)
        alerts += detect_syn_flood(recent_packets, self._known_ips)
        alerts += detect_udp_spike(recent_packets, baseline_udp_rate)

        new_device_alerts, self._known_ips = detect_new_devices(
            recent_packets, self._known_ips
        )
        alerts += new_device_alerts

        return self._deduplicate(alerts)

    def _deduplicate(self, alerts: list[Alert]) -> list[Alert]:
        """
        Suppress repeated alerts of the same (kind, source_ip) pair
        within a single detection cycle to avoid alert fatigue.
        """
        unique: list[Alert] = []
        seen: set[tuple[str, str]] = set()

        for alert in alerts:
            key = (alert.kind.value, alert.source_ip)
            if key not in seen:
                seen.add(key)
                unique.append(alert)

        return unique
