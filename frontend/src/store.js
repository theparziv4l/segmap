import { create } from 'zustand'
import { api } from './api'

let graphTimer = null

export const useStore = create((set, get) => ({
  tags: [], scope: [], machines: [], profile: null, checks: [], jobs: {},
  graph: { machines: [], blocks: [], edges: [], tags: [] },
  positions: {},
  layoutNonce: 0,
  showWeak: false,
  hiddenTags: [],
  selectedEdge: null,
  selected: {},          // "mid|iface" -> true (interfaces ticked for "run selected")
  openJobs: [], activeJob: null, drawerOpen: true,
  pendingRun: null,      // {specs, estimate, jobs} waiting for confirmation (D6)
  toast: null,

  notify: (msg, kind = 'error') => {
    set({ toast: { msg, kind, t: Date.now() } })
    setTimeout(() => { if (Date.now() - (get().toast?.t || 0) >= 5900) set({ toast: null }) }, 6000)
  },

  loadState: async () => {
    const s = await api('/state')
    set({ tags: s.tags, scope: s.scope, machines: s.machines, profile: s.profile, checks: s.checks,
      jobs: Object.fromEntries(s.jobs.map((j) => [j.id, j])) })
  },
  loadGraph: async () => set({ graph: await api('/graph') }),
  loadGraphSoon: () => { clearTimeout(graphTimer); graphTimer = setTimeout(() => get().loadGraph(), 400) },
  loadPositions: async () => set({ positions: await api('/positions') }),
  savePositions: async (positions) => { set({ positions }); await api('/positions', { method: 'PUT', body: positions }) },

  resetLayout: async () => { await get().savePositions({}); set((s) => ({ layoutNonce: s.layoutNonce + 1 })) },

  upsertJob: (job) => set((s) => ({ jobs: { ...s.jobs, [job.id]: job } })),
  openJob: (id) => set((s) => ({ openJobs: s.openJobs.includes(id) ? s.openJobs : [...s.openJobs, id], activeJob: id, drawerOpen: true })),
  closeJob: (id) => set((s) => {
    const openJobs = s.openJobs.filter((x) => x !== id)
    return { openJobs, activeJob: s.activeJob === id ? openJobs.at(-1) || null : s.activeJob }
  }),

  // Queue runs. D6: dry-run first; warn when the estimate exceeds one hour.
  run: async (specs, force = false) => {
    const { notify } = get()
    try {
      if (!force) {
        let est = 0, jobs = 0
        for (const s of specs) {
          const r = await api('/jobs', { method: 'POST', body: { ...s, dry_run: true } })
          est = Math.max(est, r.estimate_s); jobs += r.jobs
        }
        if (est > 3600) { set({ pendingRun: { specs, estimate: est, jobs } }); return }
      }
      set({ pendingRun: null })
      for (const s of specs) await api('/jobs', { method: 'POST', body: s })
    } catch (e) { notify(e.message) }
  },
}))
