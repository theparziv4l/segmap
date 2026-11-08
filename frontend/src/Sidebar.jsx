import { useState } from 'react'
import { api } from './api'
import { useStore } from './store'

const T_LABELS = ['T0 paranoid', 'T1 sneaky', 'T2 polite', 'T3 normal', 'T4 aggressive', 'T5 insane']

function Section({ title, children, open = true, right }) {
  const [o, setO] = useState(open)
  return (
    <section className="sec">
      <header onClick={() => setO(!o)}><span>{o ? '▾' : '▸'} {title}</span>{right}</header>
      {o && <div className="secbody">{children}</div>}
    </section>
  )
}

export default function Sidebar() {
  return (
    <aside className="sidebar">
      <div className="brand">SegMap <small>PCI DSS segmentation</small></div>
      <Section title="Test machines"><Machines /><AddMachine /></Section>
      <Section title="Scope & tags"><Scope /></Section>
      <Section title="Scan profile"><Profile /></Section>
    </aside>
  )
}

// ---------------- machines ----------------
function Machines() {
  const machines = useStore((s) => s.machines)
  if (!machines.length) return <p className="muted">No machines yet. Add one below.</p>
  return machines.map((m) => <Machine key={m.id} m={m} />)
}

function Machine({ m }) {
  const { loadState, loadGraph, notify, tags, selected, run, jobs } = useStore()
  const [busy, setBusy] = useState(false)
  const [trust, setTrust] = useState(null)
  const [showHidden, setShowHidden] = useState(false)
  const refresh = () => Promise.all([loadState(), loadGraph()])

  const act = async (fn) => {
    setBusy(true)
    try { await fn() } catch (e) { notify(e.message) } finally { setBusy(false); refresh() }
  }
  const connect = () => act(async () => {
    const r = await api(`/machines/${m.id}/connect`, { method: 'POST' })
    if (r.needs_trust) setTrust(r)
  })
  const doTrust = () => act(async () => {
    await api(`/machines/${m.id}/trust`, { method: 'POST', body: { fingerprint: trust.fingerprint } })
    setTrust(null)
    const r = await api(`/machines/${m.id}/connect`, { method: 'POST' })
    if (r.needs_trust) setTrust(r)
  })
  const patch = (iid, body) => act(() => api(`/interfaces/${iid}`, { method: 'PATCH', body }))
  const work = Object.values(jobs).filter((j) => j.machine_id === m.id && (j.status === 'queued' || j.status === 'running')).length
  const visible = m.interfaces.filter((i) => !i.hidden)
  const hidden = m.interfaces.filter((i) => i.hidden)
  const toggleSel = (name) => useStore.setState((s) => ({ selected: { ...s.selected, [`${m.id}|${name}`]: !s.selected[`${m.id}|${name}`] } }))

  return (
    <div className="card">
      <div className="row between">
        <div>
          <b>{m.name}</b> <span className="mono muted">{m.username}@{m.host}:{m.port}</span>
        </div>
        <span className={`badge st-${m.status}`}>{m.status}</span>
      </div>
      {m.prereq && (
        <div className="muted small">
          {m.prereq.nmap_version || 'nmap ?'} · priv: <b>{m.mode || 'none'}</b>
        </div>
      )}
      {m.paused && (
        <div className="note row between">
          <span>⏸ <b>Paused</b>{work ? ` · ${work} queued` : ''} <span className="muted small">({m.paused})</span></span>
          <button className="primary" onClick={() => act(() => api(`/machines/${m.id}/resume`, { method: 'POST' }))} disabled={busy}
            title="Reconnects on demand and continues the queue">▶ Resume</button>
        </div>
      )}
      {m.status === 'hostkey_changed' && <div className="alert">⚠ HOST KEY CHANGED — possible man-in-the-middle. Verify out of band before trusting.</div>}
      {m.error && m.status !== 'hostkey_changed' && <div className="err small">{m.error}</div>}
      {trust && (
        <div className={trust.changed ? 'alert' : 'note'}>
          {trust.changed ? '⚠ Host key CHANGED. New' : 'First connection. Host'} key fingerprint:
          <div className="mono fp">{trust.fingerprint}</div>
          <div className="row">
            <button className={trust.changed ? 'danger' : 'primary'} onClick={doTrust} disabled={busy}>Trust & connect</button>
            <button onClick={() => setTrust(null)}>Cancel</button>
          </div>
        </div>
      )}
      <div className="row">
        <button className="primary" onClick={connect} disabled={busy}>{busy ? '…' : m.mode ? 'Reconnect / re-check' : 'Connect'}</button>
        <button onClick={() => run([{ machine_id: m.id, type: 'machine', ifaces: visible.map((i) => i.name) }])} disabled={!m.mode || !visible.length}
          title="All interfaces of this machine, sequentially">▶ Run machine</button>
        {!m.paused && work > 0 && <button onClick={() => act(() => api(`/machines/${m.id}/pause`, { method: 'POST' }))}
          title="Kill the running scan (it goes back to the queue as never started) and hold the queue">⏸ Pause</button>}
        <button className="ghost" onClick={() => act(() => api(`/machines/${m.id}`, { method: 'DELETE' }))} title="Remove machine">✕</button>
      </div>
      {visible.map((i) => (
        <div key={i.id} className="iface">
          <input type="checkbox" checked={!!selected[`${m.id}|${i.name}`]} onChange={() => toggleSel(i.name)} title="Select for 'Run selected'" />
          <span className="mono"><b>{i.name}</b> {i.ipv4}</span>
          <select value={i.zone_override || ''} onChange={(e) => patch(i.id, { zone_override: e.target.value })} title="Source zone (auto = from scope)">
            <option value="">auto{!i.zone_override && i.zone ? `: ${i.zone}` : ''}</option>
            {tags.map((t) => <option key={t.name} value={t.name}>{t.name}</option>)}
          </select>
          <button className="ghost" onClick={() => run([{ machine_id: m.id, type: 'interface', ifaces: [i.name] }])} disabled={!m.mode} title="Run all checks for this interface">▶</button>
          <button className="ghost" onClick={() => patch(i.id, { hidden: true })} title="Hide interface">hide</button>
        </div>
      ))}
      {hidden.length > 0 && (
        <div className="small muted">
          <a onClick={() => setShowHidden(!showHidden)}>{hidden.length} hidden</a>
          {showHidden && hidden.map((i) => (
            <div key={i.id} className="iface"><span className="mono">{i.name} {i.ipv4}</span>
              <button className="ghost" onClick={() => patch(i.id, { hidden: false })}>show</button></div>
          ))}
        </div>
      )}
      {m.facts?.routes?.length > 0 && (
        <details className="small"><summary>routes / neighbours ({m.facts.routes.length}/{m.facts.neighbors?.length || 0})</summary>
          <pre className="mono facts">{m.facts.routes.map((r) => `${r.dst} ${r.gateway ? 'via ' + r.gateway : ''} dev ${r.dev}`).join('\n')}
{'\n'}{(m.facts.neighbors || []).map((n) => `${n.dst} ${n.lladdr || ''} ${n.dev} ${(n.state || []).join(',')}`).join('\n')}</pre>
        </details>
      )}
    </div>
  )
}

function AddMachine() {
  const { loadState, notify } = useStore()
  const empty = { name: '', host: '', port: 22, username: 'kali', password: '', key: '', passphrase: '', sudo_password: '' }
  const [f, setF] = useState(empty)
  const [open, setOpen] = useState(false)
  const [auth, setAuth] = useState('password')
  const up = (k) => (e) => setF({ ...f, [k]: k === 'port' ? Number(e.target.value) : e.target.value })
  const submit = async (e) => {
    e.preventDefault()
    try {
      await api('/machines', { method: 'POST', body: auth === 'password' ? { ...f, key: '', passphrase: '' } : { ...f, password: '' } })
      setF(empty); setOpen(false); loadState()
    } catch (err) { notify(err.message) }
  }
  if (!open) return <button onClick={() => setOpen(true)}>+ Add machine</button>
  return (
    <form className="card form" onSubmit={submit} autoComplete="off">
      <input placeholder="name (e.g. TEST-MACHINE1)" value={f.name} onChange={up('name')} required />
      <div className="row"><input placeholder="host / IP" value={f.host} onChange={up('host')} required />
        <input type="number" min="1" max="65535" value={f.port} onChange={up('port')} style={{ width: 70 }} /></div>
      <input placeholder="username" value={f.username} onChange={up('username')} required />
      <div className="row small">
        <label><input type="radio" checked={auth === 'password'} onChange={() => setAuth('password')} /> password</label>
        <label><input type="radio" checked={auth === 'key'} onChange={() => setAuth('key')} /> private key</label>
      </div>
      {auth === 'password'
        ? <input type="password" placeholder="SSH password" value={f.password} onChange={up('password')} />
        : <>
          <textarea placeholder="-----BEGIN OPENSSH PRIVATE KEY-----" rows={3} value={f.key} onChange={up('key')} />
          <input type="file" onChange={async (e) => setF({ ...f, key: await e.target.files[0].text() })} />
          <input type="password" placeholder="key passphrase (optional)" value={f.passphrase} onChange={up('passphrase')} />
        </>}
      <input type="password" placeholder="sudo password (optional, defaults to SSH password)" value={f.sudo_password} onChange={up('sudo_password')} />
      <div className="row"><button className="primary">Add</button><button type="button" onClick={() => setOpen(false)}>Cancel</button></div>
      <p className="muted small">Secrets are encrypted at rest and sent to sudo over stdin only.</p>
    </form>
  )
}

// ---------------- scope ----------------
function Scope() {
  const { scope, tags, loadState, loadGraph, notify } = useStore()
  const [text, setText] = useState('')
  const [tag, setTag] = useState('CDE')
  const [newTag, setNewTag] = useState({ name: '', color: '#2fb380' })
  const refresh = () => Promise.all([loadState(), loadGraph()])
  const add = async () => {
    try { await api('/scope', { method: 'POST', body: { text, tag } }); setText(''); refresh() } catch (e) { notify(e.message) }
  }
  const byTag = {}
  scope.forEach((s) => (byTag[s.tag] ||= []).push(s))
  const color = Object.fromEntries(tags.map((t) => [t.name, t.color]))
  return (
    <>
      <textarea rows={3} placeholder={'10.24.5.0/24\n10.24.7.10-50\n10.24.8.5'} value={text} onChange={(e) => setText(e.target.value)} />
      <div className="row">
        <select value={tag} onChange={(e) => setTag(e.target.value)}>{tags.map((t) => <option key={t.name}>{t.name}</option>)}</select>
        <button className="primary" onClick={add} disabled={!text.trim()}>Add</button>
        <label className="filebtn">upload list<input type="file" hidden onChange={async (e) => setText(await e.target.files[0].text())} /></label>
      </div>
      {Object.entries(byTag).map(([t, rows]) => (
        <div key={t} className="scopegrp">
          <div className="tagname" style={{ color: color[t] }}>■ {t} <span className="muted">({rows.length})</span></div>
          {rows.map((s) => (
            <span key={s.id} className="chip mono">{s.cidr}
              <a onClick={async () => { await api(`/scope/${s.id}`, { method: 'DELETE' }); refresh() }}>×</a></span>
          ))}
        </div>
      ))}
      <div className="row small" style={{ marginTop: 8 }}>
        <input placeholder="new tag" value={newTag.name} onChange={(e) => setNewTag({ ...newTag, name: e.target.value })} />
        <input type="color" value={newTag.color} onChange={(e) => setNewTag({ ...newTag, color: e.target.value })} />
        <button onClick={async () => { try { await api('/tags', { method: 'POST', body: newTag }); setNewTag({ ...newTag, name: '' }); refresh() } catch (e) { notify(e.message) } }}
          disabled={!newTag.name}>+ tag</button>
      </div>
      <div className="small">{tags.filter((t) => !t.builtin).map((t) => (
        <span key={t.name} className="chip" style={{ borderColor: t.color }}>{t.name}
          <a onClick={async () => { try { await api(`/tags/${encodeURIComponent(t.name)}`, { method: 'DELETE' }); refresh() } catch (e) { notify(e.message) } }}>×</a></span>
      ))}</div>
    </>
  )
}

// ---------------- profile ----------------
function Profile() {
  const { profile, checks, notify } = useStore()
  const [p, setP] = useState(null)
  const cur = p || profile
  if (!cur) return null
  const up = (k, v) => setP({ ...cur, [k]: v })
  const upAdv = (k, v) => setP({ ...cur, advanced: { ...cur.advanced, [k]: v === '' ? null : k === 'host_timeout' ? v : Number(v) } })
  const toggle = (c) => up('checks', cur.checks.includes(c) ? cur.checks.filter((x) => x !== c) : [...cur.checks, c])
  const save = async () => {
    try { const r = await api('/profile', { method: 'PUT', body: cur }); useStore.setState({ profile: r }); setP(null); notify('Profile saved', 'ok') } catch (e) { notify(e.message) }
  }
  return (
    <div className="form">
      {checks.map((c) => (
        <label key={c.name} className="check" title={`PCI DSS ${c.reqs}`}>
          <input type="checkbox" checked={cur.checks.includes(c.name)} onChange={() => toggle(c.name)} />
          {c.label} <span className="muted small">{c.reqs.split(',').slice(0, 2).join(',')}</span>
        </label>
      ))}
      <label>Timing <select value={cur.timing} onChange={(e) => up('timing', Number(e.target.value))}>
        {T_LABELS.map((l, i) => <option key={i} value={i}>-{l}</option>)}</select></label>
      <label>TCP ports <span className="small"><a onClick={() => up('tcp_ports', profile.tcp_ports_default || DEFAULT_TCP)}>default</a> · <a onClick={() => up('tcp_ports', 'all')}>all (-p-)</a></span>
        <textarea rows={2} className="mono" value={cur.tcp_ports} onChange={(e) => up('tcp_ports', e.target.value)} /></label>
      <label>UDP ports <input className="mono" value={cur.udp_ports} onChange={(e) => up('udp_ports', e.target.value)} /></label>
      <details><summary>Advanced</summary>
        <label>--max-rate <input type="number" min="1" value={cur.advanced?.max_rate ?? ''} onChange={(e) => upAdv('max_rate', e.target.value)} /></label>
        <label>--max-retries <input type="number" min="0" max="10" value={cur.advanced?.max_retries ?? ''} onChange={(e) => upAdv('max_retries', e.target.value)} /></label>
        <label>--host-timeout <input placeholder="e.g. 15m" value={cur.advanced?.host_timeout ?? ''} onChange={(e) => upAdv('host_timeout', e.target.value)} /></label>
      </details>
      <details open={cur.checks.includes('egress')}><summary>Egress (1.3.2)</summary>
        <label>Listener IP <input className="mono" placeholder="203.0.113.10" value={cur.egress_listener} onChange={(e) => up('egress_listener', e.target.value)} /></label>
        <label>Ports <input className="mono" value={cur.egress_ports} onChange={(e) => up('egress_ports', e.target.value)} /></label>
        <label>Token <input className="mono" value={cur.egress_token} onChange={(e) => up('egress_token', e.target.value)} /></label>
        <p className="muted small">Runs from interfaces whose zone is CDE. A port counts only if the listener's banner contains the token.</p>
      </details>
      <div className="row"><button className="primary" onClick={save} disabled={!p}>Save profile</button>{p && <button onClick={() => setP(null)}>Revert</button>}</div>
    </div>
  )
}

const DEFAULT_TCP = '21,22,23,25,53,80,88,110,111,135,139,143,389,443,445,465,587,636,993,995,1433,1521,2049,2375,3306,3389,5432,5900,5985,5986,6379,8000,8080,8443,9200,27017'
