/**
 * API type definitions — mirror of backend Pydantic schemas.
 * Keep in sync with app/models/schemas.py.
 *
 * Author: Mohammad Khan
 */

export type Protocol = 'TCP' | 'UDP' | 'ICMP' | 'OTHER'
export type AlertSeverity = 'CRITICAL' | 'WARNING' | 'INFO'
export type AlertKind = 'port_scan' | 'syn_flood' | 'udp_spike' | 'new_device'

export interface TrafficSnapshot {
  timestamp: string
  packets_per_sec: number
  bytes_per_sec: number
  tcp: number
  udp: number
  icmp: number
  other: number
}

export interface Alert {
  id: string
  timestamp: string
  severity: AlertSeverity
  kind: AlertKind
  title: string
  detail: string
  source_ip: string
  resolved: boolean
}

export interface TopTalker {
  ip: string
  packets: number
  bytes: number
  protocol: Protocol
  flagged: boolean
}

export interface ProtocolBreakdown {
  tcp_pct: number
  udp_pct: number
  icmp_pct: number
  other_pct: number
}

export interface SystemStats {
  packets_per_sec: number
  active_alerts: number
  flagged_ips: number
  uptime_seconds: number
}

export interface TrafficResponse {
  history: TrafficSnapshot[]
  current: TrafficSnapshot | null
}

export interface AlertsResponse {
  alerts: Alert[]
  total: number
}

export interface TopTalkersResponse {
  talkers: TopTalker[]
}

export interface StatsResponse {
  stats: SystemStats
  protocol_breakdown: ProtocolBreakdown
}
