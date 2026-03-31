/**
 * API service layer.
 *
 * All network calls go through this module. Components never call
 * fetch directly — they use the hooks in src/hooks/ instead.
 *
 * Author: Mohammad Khan
 */

import type {
  AlertsResponse,
  StatsResponse,
  TopTalkersResponse,
  TrafficResponse,
} from '@/types/api'

const BASE = '/api/v1'

class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message)
    this.name = 'ApiError'
  }
}

async function get<T>(path: string, params?: Record<string, string>): Promise<T> {
  const url = new URL(`${BASE}${path}`, window.location.origin)
  if (params) {
    Object.entries(params).forEach(([k, v]) => url.searchParams.set(k, v))
  }

  const res = await fetch(url.toString(), {
    headers: { Accept: 'application/json' },
    signal: AbortSignal.timeout(8_000),
  })

  if (!res.ok) {
    throw new ApiError(res.status, `API ${path} returned ${res.status}`)
  }

  return res.json() as Promise<T>
}

export const api = {
  getTraffic: () => get<TrafficResponse>('/traffic'),
  getAlerts: (limit = 20) => get<AlertsResponse>('/alerts', { limit: String(limit) }),
  getTopTalkers: (n = 10) => get<TopTalkersResponse>('/top-talkers', { n: String(n) }),
  getStats: () => get<StatsResponse>('/stats'),
} as const
