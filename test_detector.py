"""
Unit tests for the anomaly detection engine.

Author: Mohammad Khan
"""

import pytest

from app.models.schemas import PacketRecord, Protocol
from app.services.detector import (
    AnomalyDetector,
    detect_new_devices,
    detect_port_scan,
    detect_syn_flood,
    detect_udp_spike,
)


def _tcp(src: str, dst_port: int, flags: str = "PA") -> PacketRecord:
    return PacketRecord(
        src_ip=src, dst_ip="10.0.0.1",
        protocol=Protocol.TCP,
        src_port=54321, dst_port=dst_port,
        flags=flags,
    )


def _udp(src: str) -> PacketRecord:
    return PacketRecord(
        src_ip=src, dst_ip="10.0.0.1",
        protocol=Protocol.UDP,
        src_port=54321, dst_port=53,
    )


class TestPortScanDetector:
    def test_no_alert_below_threshold(self):
        packets = [_tcp("1.2.3.4", p) for p in range(5)]
        alerts = detect_port_scan(packets, set())
        assert alerts == []

    def test_alert_above_threshold(self):
        packets = [_tcp("1.2.3.4", p) for p in range(20)]
        alerts = detect_port_scan(packets, set())
        assert len(alerts) == 1
        assert alerts[0].source_ip == "1.2.3.4"
        assert alerts[0].kind.value == "port_scan"

    def test_multiple_sources_isolated(self):
        packets = (
            [_tcp("1.1.1.1", p) for p in range(20)]
            + [_tcp("2.2.2.2", p) for p in range(5)]
        )
        alerts = detect_port_scan(packets, set())
        assert len(alerts) == 1
        assert alerts[0].source_ip == "1.1.1.1"


class TestSynFloodDetector:
    def test_no_alert_with_completed_handshakes(self):
        packets = (
            [_tcp("1.2.3.4", 80, "S") for _ in range(250)]
            + [_tcp("1.2.3.4", 80, "SA") for _ in range(240)]
        )
        alerts = detect_syn_flood(packets, set())
        assert alerts == []

    def test_alert_on_incomplete_handshakes(self):
        packets = [_tcp("1.2.3.4", 80, "S") for _ in range(250)]
        alerts = detect_syn_flood(packets, set())
        assert len(alerts) == 1
        assert alerts[0].kind.value == "syn_flood"


class TestUdpSpikeDetector:
    def test_no_alert_at_normal_rate(self):
        packets = [_udp("1.2.3.4") for _ in range(10)]
        alerts = detect_udp_spike(packets, baseline_udp_rate=50.0)
        assert alerts == []

    def test_alert_on_spike(self):
        packets = [_udp("1.2.3.4") for _ in range(200)]
        alerts = detect_udp_spike(packets, baseline_udp_rate=20.0)
        assert len(alerts) == 1
        assert alerts[0].kind.value == "udp_spike"

    def test_no_alert_with_zero_baseline(self):
        packets = [_udp("1.2.3.4") for _ in range(500)]
        alerts = detect_udp_spike(packets, baseline_udp_rate=0.0)
        assert alerts == []


class TestNewDeviceDetector:
    def test_new_ip_triggers_alert(self):
        packets = [_tcp("192.168.1.99", 80)]
        alerts, updated = detect_new_devices(packets, known_ips=set())
        assert len(alerts) == 1
        assert "192.168.1.99" in updated

    def test_known_ip_suppressed(self):
        packets = [_tcp("192.168.1.1", 80)]
        alerts, _ = detect_new_devices(packets, known_ips={"192.168.1.1"})
        assert alerts == []


class TestAnomalyDetector:
    def test_deduplication(self):
        detector = AnomalyDetector()
        packets = [_tcp("1.2.3.4", p) for p in range(20)]
        alerts1 = detector.run(packets)
        alerts2 = detector.run(packets)
        port_scan_alerts = [a for a in alerts2 if a.kind.value == "port_scan"]
        assert len(port_scan_alerts) == 1
