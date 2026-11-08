import { useEffect, useMemo, useState } from 'react'
import { api, download, toCSV } from './api'
import { useStore } from './store'

const COLS = [
  ['evidence', 'Evidence'], ['host_ip', 'Host'], ['protocol', 'Proto'], ['port', 'Port'], ['state', 'State'],
  ['reason', 'Reason'], ['ttl', 'TTL'], ['service', 'Service'], ['issues', 'Issues'], ['check_name', 'Check'],
  ['seen_at', 'Seen'], ['job_id', 'Job'],
]
const ipKey = (ip) => (ip || '').split('.').map((x) => x.padStart(3, '0')).join('.')
const key = (r, k) => (k === 'host_ip' ? ipKey(r[k]) : k === 'evidence' ? (r[k] === 'strong' ? 0 : 1) : r[k] ?? '')

export default function EdgePanel() {
  const { selectedEdge: e, openJob, notify } = useStore()
  const [data, setData] = useState({ findings: [], flags: [] })
  const [sort, setSort] = useState(['evidence', 1])
  const [strongOnly, setStrongOnly] = useState(false)

  useEffect(() => {
    api(`/findings?machine_id=${e.machine_id}&iface=${encodeURIComponent(e.iface)}&block24=${encodeURIComponent(e.block24)}`)
      .then(setData).catch((err) => notify(err.message))
  }, [e.id, e.strong_hosts, e.weak_hosts])

  const rows = useMemo(() => {
    const r = data.findings
      .filter((f) => !strongOnly || f.evidence === 'strong')
      .map((f) => ({ ...f, issues: (f.detail.issues || []).map((i) => `${i.issue} [${i.req}]`).join('; '),
        note: f.detail.downgraded ? `downgraded: ${f.detail.downgraded}` : f.detail.unverified || '' }))
    const [k, dir] = sort
    return r.sort((a, b) => {
      const va = key(a, k), vb = key(b, k)
      return (va > vb ? 1 : va < vb ? -1 : 0) * dir
    })
  }, [data, sort, strongOnly])

  const hosts = new Set(data.findings.filter((f) => f.evidence === 'strong').map((f) => f.host_ip))
  const exportCSV = () => download(`segmap-${e.iface}-${e.block24.replace('/', '_')}.csv`,
    toCSV(rows, ['evidence', 'host_ip', 'protocol', 'port', 'state', 'reason', 'reason_ip', 'ttl', 'service', 'issues', 'note', 'check_name', 'seen_at', 'job_id', 'job_command']), 'text/csv')

  return (
    <div className="panel">
      <div className="row between">
        <h3 className="mono">{e.iface} → {e.block24}</h3>
        <button className="ghost" onClick={() => useStore.setState({ selectedEdge: null })}>✕</button>
      </div>
      <div className="small">
        source zone <b>{e.source_zone || '?'}</b> · severity <b className={`sev-${e.severity}`}>{e.severity}</b> ·
        {' '}{hosts.size} host(s) with strong evidence · {e.weak_hosts} with weak only
      </div>
      {data.flags.length > 0 && (
        <div className="alert small">{data.flags.map((f, i) => <div key={i}>⚑ <b>{f.code}</b>: {f.message}</div>)}</div>
      )}
      <div className="row">
        <label className="toggle"><input type="checkbox" checked={strongOnly} onChange={(ev) => setStrongOnly(ev.target.checked)} /> strong only</label>
        <span className="grow" />
        <button onClick={exportCSV}>Export CSV</button>
      </div>
      <div className="tablewrap">
        <table>
          <thead><tr>{COLS.map(([k, l]) => (
            <th key={k} onClick={() => setSort([k, sort[0] === k ? -sort[1] : 1])}>{l}{sort[0] === k ? (sort[1] > 0 ? ' ▲' : ' ▼') : ''}</th>
          ))}</tr></thead>
          <tbody>{rows.map((f) => (
            <tr key={f.id} className={f.evidence}>
              <td title={f.note}>{f.evidence === 'strong' ? '● strong' : '○ unverified'}{f.note ? ' *' : ''}</td>
              <td className="mono">{f.host_ip}</td><td>{f.protocol}</td><td>{f.port ?? (f.detail.extraports ? `${f.detail.extraports} ports` : '')}</td>
              <td>{f.state}</td><td>{f.reason}{f.reason_ip && f.reason_ip !== f.host_ip ? ` (${f.reason_ip})` : ''}</td><td>{f.ttl || ''}</td>
              <td title={[f.detail.product, f.detail.version].filter(Boolean).join(' ')}>{f.service}</td>
              <td className="issues">{f.issues}</td><td>{f.check_name}</td>
              <td className="small">{f.seen_at?.replace('T', ' ').slice(0, 19)}</td>
              <td><a className="mono" onClick={() => openJob(f.job_id)} title={f.job_command}>{f.job_id.slice(0, 8)}</a></td>
            </tr>
          ))}</tbody>
        </table>
      </div>
    </div>
  )
}
