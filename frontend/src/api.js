export async function api(path, { method = 'GET', body } = {}) {
  const res = await fetch(`/api${path}`, {
    method,
    headers: body !== undefined ? { 'Content-Type': 'application/json' } : undefined,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  })
  const text = await res.text()
  const data = text && res.headers.get('content-type')?.includes('json') ? JSON.parse(text) : text
  if (!res.ok) throw new Error(data?.detail ? (typeof data.detail === 'string' ? data.detail : JSON.stringify(data.detail)) : `${res.status}`)
  return data
}

// Live terminal output: listeners per job id, outside React state for speed.
const outputListeners = new Map()
export function onOutput(jobId, fn) {
  if (!outputListeners.has(jobId)) outputListeners.set(jobId, new Set())
  outputListeners.get(jobId).add(fn)
  return () => outputListeners.get(jobId)?.delete(fn)
}

export function connectWS(handlers) {
  let ws
  let retry = 0
  const open = () => {
    ws = new WebSocket(`${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}/ws`)
    ws.onopen = () => { retry = 0; handlers.onOpen?.() }
    ws.onmessage = (ev) => {
      const msg = JSON.parse(ev.data)
      if (msg.type === 'output') outputListeners.get(msg.job)?.forEach((fn) => fn(msg.data))
      else handlers[msg.type]?.(msg)
    }
    ws.onclose = () => setTimeout(open, Math.min(5000, 500 * 2 ** retry++))
  }
  open()
}

export function download(name, content, type = 'text/plain') {
  const a = document.createElement('a')
  a.href = typeof content === 'string' && content.startsWith('data:') ? content : URL.createObjectURL(new Blob([content], { type }))
  a.download = name
  a.click()
}

export function toCSV(rows, cols) {
  const esc = (v) => {
    const s = v === null || v === undefined ? '' : typeof v === 'object' ? JSON.stringify(v) : String(v)
    return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s
  }
  return [cols.join(','), ...rows.map((r) => cols.map((c) => esc(r[c])).join(','))].join('\n')
}

export const fmtDur = (s) => {
  if (s === null || s === undefined || isNaN(s)) return ''
  s = Math.round(s)
  if (s < 60) return `${s}s`
  if (s < 3600) return `${Math.floor(s / 60)}m ${s % 60}s`
  if (s < 86400) return `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m`
  return `${(s / 86400).toFixed(1)} days`
}

export const duration = (j) =>
  j.started_at ? ((j.finished_at ? new Date(j.finished_at) : new Date()) - new Date(j.started_at)) / 1000 : null
