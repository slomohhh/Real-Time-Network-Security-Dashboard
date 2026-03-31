/**
 * Dashboard — the main page, composes all panels and data hooks.
 *
 * Author: Mohammad Khan
 */

import { useAlerts } from '@/hooks/usePolling'
import { useStats } from '@/hooks/usePolling'
import { useTopTalkers } from '@/hooks/usePolling'
import { useTraffic } from '@/hooks/usePolling'
import { AlertFeed } from '@/components/alerts/AlertFeed'
import { TrafficChart } from '@/components/charts/TrafficChart'
import { ProtocolChart } from '@/components/charts/ProtocolChart'
import { StatCard } from '@/components/dashboard/StatCard'
import { TopTalkersTable } from '@/components/dashboard/TopTalkersTable'
import { Panel } from '@/components/layout/Panel'
import { TopBar } from '@/components/layout/TopBar'
import { formatUptime } from '@/utils/format'
import styles from './Dashboard.module.css'

export function Dashboard() {
  const traffic    = useTraffic()
  const alerts     = useAlerts()
  const talkers    = useTopTalkers()
  const statsQuery = useStats()

  const connected = !statsQuery.error
  const stats     = statsQuery.data?.stats ?? null
  const breakdown = statsQuery.data?.protocol_breakdown ?? null
  const history   = traffic.data?.history ?? []
  const alertList = alerts.data?.alerts ?? []
  const talkerList = talkers.data?.talkers ?? []

  const activeAlerts = alertList.filter(a => !a.resolved)
  const critCount    = activeAlerts.filter(a => a.severity === 'CRITICAL').length
  const warnCount    = activeAlerts.filter(a => a.severity === 'WARNING').length

  return (
    <div className={styles.root}>
      <TopBar stats={stats} connected={connected} />

      {/* Stat cards row */}
      <div className={styles.metrics}>
        <StatCard
          label="Packets / sec"
          value={stats ? stats.packets_per_sec.toLocaleString() : '—'}
          sub="live · 1s avg"
          tone="ok"
        />
        <StatCard
          label="Active alerts"
          value={String(activeAlerts.length)}
          sub={`${critCount} critical · ${warnCount} warning`}
          tone={critCount > 0 ? 'alert' : warnCount > 0 ? 'warn' : 'ok'}
        />
        <StatCard
          label="Flagged IPs"
          value={stats ? String(stats.flagged_ips) : '—'}
          sub="unique sources"
          tone={stats && stats.flagged_ips > 0 ? 'warn' : 'neutral'}
        />
        <StatCard
          label="Uptime"
          value={stats ? formatUptime(stats.uptime_seconds) : '—'}
          sub="since last restart"
          tone="neutral"
        />
      </div>

      {/* Traffic chart + alerts */}
      <div className={styles.mainGrid}>
        <Panel title="Live traffic" subtitle="pps · 60s window">
          <TrafficChart history={history} />
        </Panel>
        <Panel title="Active alerts">
          <AlertFeed alerts={activeAlerts} />
        </Panel>
      </div>

      {/* Protocol breakdown + top talkers */}
      <div className={styles.bottomGrid}>
        <Panel title="Protocol breakdown">
          {breakdown
            ? <ProtocolChart breakdown={breakdown} />
            : <p className={styles.loading}>Loading…</p>
          }
        </Panel>
        <Panel title="Top talkers">
          <TopTalkersTable talkers={talkerList} />
        </Panel>
      </div>
    </div>
  )
}
