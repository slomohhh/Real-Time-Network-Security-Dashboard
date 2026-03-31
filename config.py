"""
Application configuration.

Author: Mohammad Khan
"""

from functools import lru_cache
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    # Server
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    ENV: Literal["development", "production"] = "development"

    # CORS
    ALLOWED_ORIGINS: list[str] = [
        "http://localhost:5173",
        "http://localhost:3000",
    ]

    # Packet capture
    NETWORK_INTERFACE: str = "lo"      # Override with e.g. "eth0", "en0"
    SIMULATION_MODE: bool = True        # Set False to use live Scapy capture
    CAPTURE_FILTER: str = "ip"          # BPF filter string

    # Anomaly detection thresholds
    PORT_SCAN_WINDOW_SECS: int = 10
    PORT_SCAN_THRESHOLD: int = 15       # Unique ports from one IP in window
    SYN_FLOOD_WINDOW_SECS: int = 5
    SYN_FLOOD_THRESHOLD: int = 200      # SYN packets from one IP in window
    UDP_SPIKE_WINDOW_SECS: int = 10
    UDP_SPIKE_MULTIPLIER: float = 3.0   # x times baseline to flag

    # Ring buffer capacity (seconds of history kept in memory)
    TRAFFIC_HISTORY_SECS: int = 60

    # Alert retention
    MAX_ALERTS: int = 100


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
