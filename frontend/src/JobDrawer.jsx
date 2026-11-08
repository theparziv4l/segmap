import { useEffect, useRef, useState } from 'react'
import { Terminal } from '@xterm/xterm'
import { FitAddon } from '@xterm/addon-fit'
import { api, duration, fmtDur, onOutput } from './api'
import { useStore } from './store'

const fmtTime = (t) => (t ? t.replace('T', ' ').slice(0, 19) : '')

export default function JobDrawer() {
  const { jobs, machines, drawerOpen, openJobs, activeJob, openJob, closeJob, notify } = useStore()
  const [filter, setFilter] = useState('all')
  const [, tick] = useState(0)
  useEffect(() => { const t = setInterval(() => tick((x) => x + 1), 1000); return () => clearInterval(t) }, [])
  const mname = Object.fromEntries(machines.map((m) => [m.id, m.name]))
  const list = Object.values(jobs)
    .filter((j) => filter === 'all' || (filter === 'active' ? ['queued', 'running'].includes(j.status) : j.status === filter))
    .sort((a, b) => b.batch_id - a.batch_id || a.seq - b.seq)
    .slice(0, 400)
  const counts = Object.values(jobs).reduce((c, j) => ({ ...c, [j.status]: (c[j.status] || 0) + 1 }), {})
  const kill = async (id) => { try { await api(`/jobs/${id}/kill`, { method: 'POST' }) } catch (e) { notify(e.message) } }

  return (
    <div className={`drawer ${drawerOpen ? 'open' : ''}`}>
      <div className="drawer-head" onClick={() => useStore.setState({ drawerOpen: !drawerOpen })}>
        <span>{drawerOpen ? '▾' : '▸'} Jobs</span>
        {['running', 'queued', 'done', 'failed', 'killed'].map((s) => counts[s] ? <span key={s} className={`badge js-${s}`}>{s} {counts[s]}</span> : null)}
      </div>
      {drawerOpen && (
        <div className="drawer-body">
          <div className="joblist">
            <div className="row small">
              {['all', 'active', 'done', 'failed', 'killed'].map((f) => (
                <a key={f} className={filter === f ? 'on' : ''} onClick={() => setFilter(f)}>{f}</a>
              ))}
            </div>
            <table>
              <thead><tr><th>status</th><th>machine</th><th>iface</th><th>check</th><th>target</th><th>dur</th><th>exit</th><th /></tr></thead>
              <tbody>{list.map((j) => (
                <tr key={j.id} className={activeJob === j.id ? 'sel' : ''} onClick={() => openJob(j.id)}>
                  <td><span className={`badge js-${j.status}`}>{j.status}</span></td>
                  <td>{mname[j.machine_id] || j.machine_id}</td><td className="mono">{j.iface}</td><td>{j.check_name}</td>
                  <td className="mono">{j.block24}</td><td>{fmtDur(duration(j))}</td><td>{j.exit_code ?? ''}</td>
                  <td>{['queued', 'running'].includes(j.status) && (
                    <button className="kill sm" onClick={(e) => { e.stopPropagation(); kill(j.id) }} title="Kill this job">■</button>)}</td>
                </tr>
              ))}</tbody>
            </table>
          </div>
          <div className="terms">
            <div className="tabs">{openJobs.map((id) => (
              <span key={id} className={`tab ${activeJob === id ? 'on' : ''}`} onClick={() => useStore.setState({ activeJob: id })}>
                <span className={`dot js-${jobs[id]?.status}`} /> {jobs[id]?.iface} {jobs[id]?.check_name} {jobs[id]?.block24}
                <a onClick={(e) => { e.stopPropagation(); closeJob(id) }}>×</a>
              </span>
            ))}</div>
            {activeJob && jobs[activeJob] ? <TermView key={activeJob} job={jobs[activeJob]} /> : <div className="muted pad">Click a job to view its terminal output.</div>}
          </div>
        </div>
      )}
    </div>
  )
}

function TermView({ job }) {
  const ref = useRef(null)
  useEffect(() => {
    const term = new Terminal({ convertEol: true, fontSize: 12, fontFamily: 'JetBrains Mono, ui-monospace, monospace',
      theme: { background: '#0b0c0f', foreground: '#d6d8e0' }, scrollback: 20000, disableStdin: true })
    const fit = new FitAddon()
    term.loadAddon(fit)
    term.open(ref.current)
    fit.fit()
    // ponytail: chunks arriving while the log is fetched may print twice; harmless for a viewer
    const pending = []
    let loaded = false
    const off = onOutput(job.id, (d) => (loaded ? term.write(d) : pending.push(d)))
    api(`/jobs/${job.id}/log`).then((text) => { term.write(text || ''); loaded = true; pending.forEach((d) => term.write(d)) })
    const ro = new ResizeObserver(() => fit.fit())
    ro.observe(ref.current)
    return () => { off(); ro.disconnect(); term.dispose() }
  }, [job.id])
  return (
    <div className="termview">
      <div className="termmeta small">
        <span className={`badge js-${job.status}`}>{job.status}</span>
        <span>start {fmtTime(job.started_at) || '—'}</span><span>end {fmtTime(job.finished_at) || '—'}</span>
        <span>{fmtDur(duration(job))}</span><span>exit {job.exit_code ?? '—'}</span>{job.pgid && <span>pgid {job.pgid}</span>}
        {job.error && <span className="err">{job.error}</span>}
      </div>
      <div className="mono cmdline" title="exact command line">{job.command ? `$ ${job.command}` : `(queued) ${job.check_name} → ${(job.targets || []).join(' ')}`}</div>
      {job.flags?.length > 0 && <div className="alert small">{job.flags.map((f, i) => <div key={i}>⚑ {f.message}</div>)}</div>}
      <div className="term" ref={ref} />
    </div>
  )
}
