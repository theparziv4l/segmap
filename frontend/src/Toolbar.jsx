import { useReactFlow, getNodesBounds, getViewportForBounds } from '@xyflow/react'
import { toPng, toSvg } from 'html-to-image'
import { api, download } from './api'
import { useStore } from './store'
import { describeId } from './Graph'

export default function Toolbar() {
  const { selected, run, showWeak, view, saveView, toggleHidden, graph, tags, jobs, machines, notify, resetLayout, loadGraph, loadState } = useStore()
  const rf = useReactFlow()
  const active = Object.values(jobs).filter((j) => j.status === 'running' || j.status === 'queued').length
  const paused = machines.filter((m) => m.paused).length
  const call = async (path, msg) => { try { await api(path, { method: 'POST' }); notify(msg, 'ok'); loadState() } catch (e) { notify(e.message) } }

  const runSelected = () => {
    const byMachine = {}
    Object.entries(selected).filter(([, v]) => v).forEach(([k]) => {
      const [mid, iface] = k.split('|')
      ;(byMachine[mid] ||= []).push(iface)
    })
    const specs = Object.entries(byMachine).map(([mid, ifaces]) => ({ machine_id: Number(mid), type: 'interface', ifaces }))
    if (!specs.length) return notify('Tick interfaces in the sidebar first')
    run(specs)
  }
  const masterKill = async () => {
    try { const r = await api('/kill-all', { method: 'POST' }); notify(`Master kill: running jobs terminated, ${r.cancelled} queued cancelled`, 'ok') } catch (e) { notify(e.message) }
  }
  const exportImage = async (kind) => {
    const bounds = getNodesBounds(rf.getNodes())
    const w = Math.max(800, bounds.width + 160), h = Math.max(600, bounds.height + 160)
    const vp = getViewportForBounds(bounds, w, h, 0.1, 2, 0.05)
    const el = document.querySelector('#graph .react-flow__viewport')
    const opts = { backgroundColor: '#111216', width: w, height: h,
      style: { width: `${w}px`, height: `${h}px`, transform: `translate(${vp.x}px, ${vp.y}px) scale(${vp.zoom})` } }
    download(`segmap-graph.${kind}`, await (kind === 'png' ? toPng(el, opts) : toSvg(el, opts)))
  }

  return (
    <div className="toolbar">
      <button className="primary" onClick={runSelected}>▶ Run selected</button>
      <button className="kill" onClick={masterKill} title="Kill every running scan and cancel the queue">■ MASTER KILL{active ? ` (${active})` : ''}</button>
      <button onClick={() => call('/pause-all', 'Pausing: running scans go back to the queue')} disabled={!active}
        title="Kill running scans (they go back to the queue as never started) and hold every queue">⏸ Pause all</button>
      {paused > 0 && <button className="primary" onClick={() => call('/resume-all', 'Resumed')} title="Reconnect and continue every paused queue">▶ Resume all ({paused})</button>}
      <span className="sep" />
      <button onClick={resetLayout}>Layout reset</button>
      <label className="toggle"><input type="checkbox" checked={showWeak} onChange={(e) => useStore.setState({ showWeak: e.target.checked })} /> weak edges</label>
      <span className="sep" />
      {[...tags.map((t) => t.name), 'unscoped'].map((t) => {
        const color = tags.find((x) => x.name === t)?.color || '#8b8d98'
        return <button key={t} className={`tagchip ${view.hidden.includes(`t:${t}`) ? 'off' : ''}`} style={{ borderColor: color, color }} onClick={() => toggleHidden(`t:${t}`)}>{t}</button>
      })}
      <span className="grow" />
      {view.hidden.length > 0 && (
        <div className="menu">
          <button title="Hidden items are not drawn and not in PNG/SVG exports">Hidden ({view.hidden.length}) ▾</button>
          <div className="menu-items">
            {view.hidden.map((id) => <a key={id} onClick={() => toggleHidden(id)} title="Click to unhide">👁 {describeId(graph, view.labels, id)}</a>)}
            <a onClick={() => saveView({ ...view, hidden: [] })}><b>Unhide all</b></a>
          </div>
        </div>
      )}
      <div className="menu">
        <button>Export ▾</button>
        <div className="menu-items">
          <a onClick={() => exportImage('png')}>Graph PNG</a>
          <a onClick={() => exportImage('svg')}>Graph SVG</a>
          <a href="/api/export/findings.json">Findings JSON</a>
          <a href="/api/export/findings.csv">Findings CSV</a>
          <a href="/api/export/timeline.csv" title="PCI DSS 11.5.1: give to the SOC to match IDS alerts">Scan timeline CSV</a>
          <a href="/api/export/audit.csv" title="Every remote command: who, when (UTC + local), from machine/iface/zone, to scope block/tag">Command audit log CSV</a>
          <a className="danger-text" onClick={async () => { await api('/findings', { method: 'DELETE' }); loadGraph(); notify('Results cleared', 'ok') }}>Clear all results</a>
        </div>
      </div>
    </div>
  )
}
