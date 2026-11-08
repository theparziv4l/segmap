import { useReactFlow, getNodesBounds, getViewportForBounds } from '@xyflow/react'
import { toPng, toSvg } from 'html-to-image'
import { api, download } from './api'
import { useStore } from './store'

export default function Toolbar() {
  const { selected, run, showWeak, hiddenTags, tags, jobs, notify, resetLayout, loadGraph } = useStore()
  const rf = useReactFlow()
  const active = Object.values(jobs).filter((j) => j.status === 'running' || j.status === 'queued').length

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
  const toggleTag = (t) => useStore.setState({ hiddenTags: hiddenTags.includes(t) ? hiddenTags.filter((x) => x !== t) : [...hiddenTags, t] })

  return (
    <div className="toolbar">
      <button className="primary" onClick={runSelected}>▶ Run selected</button>
      <button className="kill" onClick={masterKill} title="Kill every running scan and cancel the queue">■ MASTER KILL{active ? ` (${active})` : ''}</button>
      <span className="sep" />
      <button onClick={resetLayout}>Layout reset</button>
      <label className="toggle"><input type="checkbox" checked={showWeak} onChange={(e) => useStore.setState({ showWeak: e.target.checked })} /> weak edges</label>
      <span className="sep" />
      {[...tags.map((t) => t.name), 'unscoped'].map((t) => {
        const color = tags.find((x) => x.name === t)?.color || '#8b8d98'
        return <button key={t} className={`tagchip ${hiddenTags.includes(t) ? 'off' : ''}`} style={{ borderColor: color, color }} onClick={() => toggleTag(t)}>{t}</button>
      })}
      <span className="grow" />
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
