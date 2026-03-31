"""
Packet collector — live capture (Scapy) or deterministic simulation.

The collector runs as a background asyncio task, aggregating packets
into per-second snapshots and triggering anomaly detection on each tick.

Author: Mohammad Khan
"""

from __future__ import annotations

import asyncio
import logging
import random
import time
from collections import defaultdict, deque
from datetime import datetime, timezone

from app.core.config import settings
from app.models.schemas import (
    Alert,
    AlertSeverity,
    PacketRecord,
    Protocol,
    TrafficSnapshot,
    TopTalker,
)
from app.services.detector import AnomalyDetector

logger = logging.getLogger(__name__)

# Realistic private-range IP pool for simulation
_SIMULATED_IPS = [
    "192.168.1.10", "192.168.1.20", "192.168.1.44",
    "10.0.0.5",     "10.0.0.88",    "10.0.0.105",
    "10.0.0.201",   "172.16.0.12",  "172.16.0.55",
]
_COMMON_PORTS = [80, 443, 22, 3306, 5432, 8080, 53, 123, 8443]


class PacketCollector:
    """
    Aggregates network packets into 1-second traffic snapshots,
    maintains a rolling history buffer, and runs anomaly detection.
    """

    def __init__(self) -> None:
        self._started_at: float = time.monotonic()
        self._history: deque[TrafficSnapshot] = deque(
            maxlen=settings.TRAFFIC_HISTORY_SECS
        )
        self._alerts: deque[Alert] = deque(maxlen=settings.MAX_ALERTS)
        self._packet_buffer: list[PacketRecord] = []
        self._talker_counts: dict[str, dict[str, int]] = defaultdict(
            lambda: {"packets": 0, "bytes": 0}
        )
        self._detector = AnomalyDetector()
        self._task: asyncio.Task | None = None
        self._lock = asyncio.Lock()

        # Rolling UDP baseline (exponential moving average)
        self._udp_baseline: float = 50.0
        self._ema_alpha: float = 0.1

        # Inject a scripted attack scenario for demo purposes
        self._attack_tick: int = 0
        self._inject_attack_at: int = random.randint(15, 30)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        self._task = asyncio.create_task(self._run_loop(), name="packet_collector")

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    # ------------------------------------------------------------------
    # Public read API (called by route handlers)
    # ------------------------------------------------------------------

    def get_history(self) -> list[TrafficSnapshot]:
        return list(self._history)

    def get_current(self) -> TrafficSnapshot | None:
        return self._history[-1] if self._history else None

    def get_alerts(self) -> list[Alert]:
        return list(reversed(self._alerts))

    def get_top_talkers(self, n: int = 10) -> list[TopTalker]:
        flagged_ips = {a.source_ip for a in self._alerts if not a.resolved}
        talkers = [
            TopTalker(
                ip=ip,
                packets=counts["packets"],
                bytes=counts["bytes"],
                protocol=Protocol.TCP,  # simplified; extend with per-IP protocol tracking
                flagged=ip in flagged_ips,
            )
            for ip, counts in self._talker_counts.items()
        ]
        return sorted(talkers, key=lambda t: t.packets, reverse=True)[:n]

    @property
    def uptime_seconds(self) -> float:
        return time.monotonic() - self._started_at

    @property
    def flagged_ip_count(self) -> int:
        return len({a.source_ip for a in self._alerts if not a.resolved})

    # ------------------------------------------------------------------
    # Internal loop
    # ------------------------------------------------------------------

    async def _run_loop(self) -> None:
        if settings.SIMULATION_MODE:
            logger.info("Running in simulation mode")
            await self._simulation_loop()
        else:
            logger.info("Running live capture on interface: %s", settings.NETWORK_INTERFACE)
            await self._live_capture_loop()

    async def _simulation_loop(self) -> None:
        while True:
            tick_packets = self._generate_tick_packets()
            await self._process_tick(tick_packets)
            self._attack_tick += 1
            await asyncio.sleep(1.0)

    async def _live_capture_loop(self) -> None:
        """
        Live Scapy capture. Runs Scapy's blocking sniff() in a thread
        so it never blocks the event loop.
        """
        try:
            from scapy.all import AsyncSniffer, IP, TCP, UDP, ICMP
        except ImportError:
            logger.error("Scapy not installed — falling back to simulation mode")
            await self._simulation_loop()
            return

        def packet_callback(pkt):
            if not pkt.haslayer(IP):
                return
            ip = pkt[IP]
            proto = Protocol.OTHER
            src_port = dst_port = None
            flags = ""
            size = len(pkt)

            if pkt.haslayer(TCP):
                proto = Protocol.TCP
                src_port = pkt[TCP].sport
                dst_port = pkt[TCP].dport
                flags = str(pkt[TCP].flags)
            elif pkt.haslayer(UDP):
                proto = Protocol.UDP
                src_port = pkt[UDP].sport
                dst_port = pkt[UDP].dport
            elif pkt.haslayer(ICMP):
                proto = Protocol.ICMP

            record = PacketRecord(
                src_ip=ip.src,
                dst_ip=ip.dst,
                protocol=proto,
                src_port=src_port,
                dst_port=dst_port,
                size_bytes=size,
                flags=flags,
            )
            asyncio.get_event_loop().call_soon_threadsafe(
                self._packet_buffer.append, record
            )

        sniffer = AsyncSniffer(
            iface=settings.NETWORK_INTERFACE,
            filter=settings.CAPTURE_FILTER,
            prn=packet_callback,
            store=False,
        )
        sniffer.start()

        try:
            while True:
                async with self._lock:
                    batch, self._packet_buffer = self._packet_buffer[:], []
                if batch:
                    await self._process_tick(batch)
                await asyncio.sleep(1.0)
        finally:
            sniffer.stop()

    # ------------------------------------------------------------------
    # Tick processing
    # ------------------------------------------------------------------

    async def _process_tick(self, packets: list[PacketRecord]) -> None:
        counts: dict[Protocol, int] = defaultdict(int)
        total_bytes = 0

        for pkt in packets:
            counts[pkt.protocol] += 1
            total_bytes += pkt.size_bytes
            self._talker_counts[pkt.src_ip]["packets"] += 1
            self._talker_counts[pkt.src_ip]["bytes"] += pkt.size_bytes

        snapshot = TrafficSnapshot(
            timestamp=datetime.now(timezone.utc),
            packets_per_sec=len(packets),
            bytes_per_sec=total_bytes,
            tcp=counts[Protocol.TCP],
            udp=counts[Protocol.UDP],
            icmp=counts[Protocol.ICMP],
            other=counts[Protocol.OTHER],
        )
        self._history.append(snapshot)

        # Update UDP baseline via EMA
        current_udp_rate = counts[Protocol.UDP]
        self._udp_baseline = (
            self._ema_alpha * current_udp_rate
            + (1 - self._ema_alpha) * self._udp_baseline
        )

        # Run anomaly detection on recent window
        window_secs = settings.PORT_SCAN_WINDOW_SECS
        recent = packets  # In real mode, you'd pull from a time-windowed buffer
        new_alerts = self._detector.run(recent, self._udp_baseline)
        for alert in new_alerts:
            self._alerts.append(alert)
            logger.info("Alert [%s]: %s from %s", alert.severity, alert.title, alert.source_ip)

    # ------------------------------------------------------------------
    # Simulation helpers
    # ------------------------------------------------------------------

    def _generate_tick_packets(self) -> list[PacketRecord]:
        """
        Generate a realistic mix of packets for one second.
        Injects scripted attack traffic at predetermined ticks
        to demonstrate anomaly detection.
        """
        packets: list[PacketRecord] = []
        n_normal = random.randint(120, 280)

        for _ in range(n_normal):
            src = random.choice(_SIMULATED_IPS)
            dst = random.choice(_SIMULATED_IPS)
            proto = random.choices(
                [Protocol.TCP, Protocol.UDP, Protocol.ICMP, Protocol.OTHER],
                weights=[61, 27, 9, 3],
            )[0]
            src_port = random.randint(1024, 65535)
            dst_port = random.choice(_COMMON_PORTS)
            flags = "PA" if proto == Protocol.TCP else ""
            packets.append(PacketRecord(
                src_ip=src,
                dst_ip=dst,
                protocol=proto,
                src_port=src_port,
                dst_port=dst_port,
                size_bytes=random.randint(64, 1500),
                flags=flags,
            ))

        # Inject scripted attack scenario
        if self._attack_tick == self._inject_attack_at:
            packets += self._inject_port_scan("192.168.1.44")
        elif self._attack_tick == self._inject_attack_at + 5:
            packets += self._inject_syn_flood("10.0.0.201")
        elif self._attack_tick == self._inject_attack_at + 12:
            packets += self._inject_udp_spike("10.0.0.88")
            self._inject_attack_at = self._attack_tick + random.randint(30, 60)

        return packets

    def _inject_port_scan(self, src_ip: str) -> list[PacketRecord]:
        logger.debug("Injecting port scan scenario from %s", src_ip)
        return [
            PacketRecord(
                src_ip=src_ip,
                dst_ip="10.0.0.1",
                protocol=Protocol.TCP,
                src_port=random.randint(1024, 65535),
                dst_port=port,
                size_bytes=60,
                flags="S",
            )
            for port in range(1, settings.PORT_SCAN_THRESHOLD + 5)
        ]

    def _inject_syn_flood(self, src_ip: str) -> list[PacketRecord]:
        logger.debug("Injecting SYN flood scenario from %s", src_ip)
        return [
            PacketRecord(
                src_ip=src_ip,
                dst_ip="10.0.0.1",
                protocol=Protocol.TCP,
                src_port=random.randint(1024, 65535),
                dst_port=80,
                size_bytes=60,
                flags="S",
            )
            for _ in range(settings.SYN_FLOOD_THRESHOLD + 20)
        ]

    def _inject_udp_spike(self, src_ip: str) -> list[PacketRecord]:
        logger.debug("Injecting UDP spike scenario from %s", src_ip)
        return [
            PacketRecord(
                src_ip=src_ip,
                dst_ip="10.0.0.1",
                protocol=Protocol.UDP,
                src_port=random.randint(1024, 65535),
                dst_port=53,
                size_bytes=random.randint(100, 900),
            )
            for _ in range(int(self._udp_baseline * settings.UDP_SPIKE_MULTIPLIER * 1.5))
        ]
