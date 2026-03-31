/**
 * Custom hooks for polling API endpoints.
 *
 * Each hook encapsulates a single resource: fetch on mount,
 * poll on interval, expose loading/error state.
 *
 * Author: Mohammad Khan
 */

import { useCallback, useEffect, useRef, useState } from 'react'
import { api } from '@/services/api'
import type {
  AlertsResponse,
  StatsResponse,
  TopTalkersResponse,
  TrafficResponse,
} from '@/types/api'

interface PollState<T> {
  data: T | null
  loading: boolean
  error: string | null
}

function usePoll<T>(
  fetcher: () => Promise<T>,
  intervalMs: number,
): PollState<T> {
  const [state, setState] = useState<PollState<T>>({
    data: null,
    loading: true,
    error: null,
  })
  const fetcherRef = useRef(fetcher)
  fetcherRef.current = fetcher

  const execute = useCallback(async () => {
    try {
      const data = await fetcherRef.current()
      setState({ data, loading: false, error: null })
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unknown error'
      setState(prev => ({ ...prev, loading: false, error: message }))
    }
  }, [])

  useEffect(() => {
    void execute()
    const id = setInterval(() => void execute(), intervalMs)
    return () => clearInterval(id)
  }, [execute, intervalMs])

  return state
}

export const useTraffic = () =>
  usePoll<TrafficResponse>(api.getTraffic, 1_000)

export const useAlerts = () =>
  usePoll<AlertsResponse>(api.getAlerts, 2_000)

export const useTopTalkers = () =>
  usePoll<TopTalkersResponse>(api.getTopTalkers, 3_000)

export const useStats = () =>
  usePoll<StatsResponse>(api.getStats, 1_000)
