import { useEffect, useMemo, useState } from 'react'
import { ReactFlow, Background, Controls, MiniMap, Handle, Position, MarkerType, useReactFlow, useNodesState, useEdgesState } from '@xyflow/react'
import ELK from 'elkjs/lib/elk.bundled.js'
import { useStore } from './store'

const elk = new ELK()
const SEV = { critical: '#e5484d', high: '#f76b15', info: '#c7c9d1', none: '#6b6e7a' }
const IFACE = { width: 170, height: 58 }
const BLOCK = { width: 170, height: 70 }
const GROUP_PAD = '[top=44,left=18,bottom=18,right=18]'

export const nodeId = {
  machine: (id) => `m:${id}`, iface: (mid, name) => `i:${mid}|${name}`, tag: (t) => `t:${t}`, block: (c) => `b:${c}`,
}

function MachineNode({ data }) {
  return <div className="g-label"><b>{data.name}</b> <span className="mono">{data.host}</span> <span className={`dot st-${data.status}`} /></div>
}
function TagNode({ data }) {
  return <div className="g-label" style={{ color: data.color }}><b>{data.tag}</b> <span className="muted">{data.count} × /24</span></div>
}
function IfaceNode({ data }) {
  return (
    <div className="n-iface">
      <div><b>{data.name}</b> <span className="mono">{data.ipv4}</span></div>
      <span className="zone" style={{ background: data.zoneColor || '#33353f' }}>{data.zone || 'zone ?'}</span>
      <Handle type="source" position={Position.Bottom} />
    </div>
  )
}
function BlockNode({ data }) {
  return (
    <div className={`n-block ${data.violation ? 'violation' : ''} ${data.scanned ? '' : 'unscanned'}`} style={{ borderColor: data.color }}>
      <Handle type="target" position={Position.Top} />
      <div className="mono"><b>{data.cidr}</b></div>
      <div className="small" style={{ color: data.color }}>{data.tag}</div>
      {data.flags.length > 0 && (
        <div className="flags" title={data.flags.map((f) => `${f.iface}: ${f.message}`).join('\n')}>⚑ {[...new Set(data.flags.map((f) => f.code))].join(', ')}</div>
      )}
    </div>
  )
}
const nodeTypes = { machine: MachineNode, tagGroup: TagNode, iface: IfaceNode, block: BlockNode }

function visibleEdges(graph, hiddenTags, showWeak) {
  const blockTag = Object.fromEntries(graph.blocks.map((b) => [b.cidr, b.tag]))
  const ifaceSet = new Set(graph.machines.flatMap((m) => m.interfaces.map((i) => nodeId.iface(m.id, i.name))))
  return graph.edges.filter((e) => (e.strong_hosts > 0 || (showWeak && e.weak_hosts > 0))
    && !hiddenTags.includes(blockTag[e.block24]) && ifaceSet.has(nodeId.iface(e.machine_id, e.iface)))
}

async function layout(graph, hiddenTags, showWeak) {
  const tagColor = Object.fromEntries(graph.tags.map((t) => [t.name, t.color]))
  const tagRank = Object.fromEntries(graph.tags.map((t) => [t.name, t.rank]))
  const groups = {}
  graph.blocks.filter((b) => !hiddenTags.includes(b.tag)).forEach((b) => (groups[b.tag] ||= []).push(b))
  const edges = visibleEdges(graph, hiddenTags, showWeak)
  const elkGraph = {
    id: 'root',
    layoutOptions: {
      'elk.algorithm': 'layered', 'elk.direction': 'DOWN', 'elk.hierarchyHandling': 'INCLUDE_CHILDREN',
      'elk.partitioning.activate': 'true', // machines always above networks
      'elk.layered.spacing.nodeNodeBetweenLayers': '140', 'elk.spacing.nodeNode': '36', 'elk.padding': '[top=20,left=20,bottom=20,right=20]',
    },
    children: [
      ...graph.machines.map((m) => ({
        id: nodeId.machine(m.id), layoutOptions: { 'elk.padding': GROUP_PAD, 'elk.partitioning.partition': '0' }, width: 220, height: 100,
        children: m.interfaces.map((i) => ({ id: nodeId.iface(m.id, i.name), ...IFACE })),
      })),
      ...Object.entries(groups).sort((a, b) => (tagRank[a[0]] ?? 99) - (tagRank[b[0]] ?? 99)).map(([tag, blocks]) => ({
        id: nodeId.tag(tag), layoutOptions: { 'elk.padding': GROUP_PAD, 'elk.partitioning.partition': '1' }, width: 220, height: 110,
        children: blocks.map((b) => ({ id: nodeId.block(b.cidr), ...BLOCK })),
      })),
    ],
    edges: edges.map((e) => ({ id: e.id, sources: [nodeId.iface(e.machine_id, e.iface)], targets: [nodeId.block(e.block24)] })),
  }
  const res = await elk.layout(elkGraph)
  const pos = {}
  const walk = (n) => (n.children || []).forEach((c) => { pos[c.id] = c; walk(c) })
  walk(res)

  const critical = new Set(edges.filter((e) => e.severity === 'critical' || e.severity === 'high').map((e) => e.block24))
  const nodes = []
  graph.machines.forEach((m) => {
    const g = pos[nodeId.machine(m.id)]
    nodes.push({ id: g.id, type: 'machine', position: { x: g.x, y: g.y }, data: m, className: 'n-group machine',
      style: { width: g.width, height: g.height } })
    m.interfaces.forEach((i) => {
      const p = pos[nodeId.iface(m.id, i.name)]
      nodes.push({ id: p.id, type: 'iface', parentId: g.id, position: { x: p.x, y: p.y },
        data: { ...i, machine_id: m.id, zoneColor: tagColor[i.zone] }, style: IFACE })
    })
  })
  Object.entries(groups).forEach(([tag, blocks]) => {
    const g = pos[nodeId.tag(tag)]
    nodes.push({ id: g.id, type: 'tagGroup', position: { x: g.x, y: g.y }, data: { tag, color: tagColor[tag] || '#8b8d98', count: blocks.length },
      className: 'n-group taggroup', style: { width: g.width, height: g.height, borderColor: tagColor[tag] || '#8b8d98' } })
    blocks.forEach((b) => {
      const p = pos[nodeId.block(b.cidr)]
      nodes.push({ id: p.id, type: 'block', parentId: g.id, position: { x: p.x, y: p.y },
        data: { ...b, color: tagColor[b.tag] || '#8b8d98', violation: critical.has(b.cidr) }, style: BLOCK })
    })
  })
  return { nodes, edges }
}

function toFlowEdge(e, selectedId) {
  const strong = e.strong_hosts > 0
  const color = strong ? SEV[e.severity] || SEV.info : SEV.none
  const label = strong
    ? `${e.strong_hosts}h · ${e.strong_ports}p${e.issues ? ` · ⚠${e.issues}` : ''}`
    : `${e.weak_hosts} weak (unverified)`
  return {
    id: e.id, source: nodeId.iface(e.machine_id, e.iface), target: nodeId.block(e.block24), data: e, label,
    animated: false, selected: e.id === selectedId,
    style: { stroke: color, strokeWidth: e.id === selectedId ? 3.5 : strong ? 2 : 1.2, strokeDasharray: strong ? undefined : '6 5' },
    markerEnd: { type: MarkerType.ArrowClosed, color, width: 18, height: 18 },
    labelStyle: { fill: color, fontSize: 11, fontFamily: 'var(--mono)' },
    labelBgStyle: { fill: 'var(--bg)', fillOpacity: 0.85 },
  }
}

export default function Graph() {
  const { graph, hiddenTags, showWeak, savePositions, selectedEdge, layoutNonce } = useStore()
  const [nodes, setNodes, onNodesChange] = useNodesState([])
  const [edges, setEdges, onEdgesChange] = useEdgesState([])
  const [raw, setRaw] = useState([])
  const rf = useReactFlow()
  const structure = useMemo(() => JSON.stringify({
    m: graph.machines.map((m) => [m.id, m.interfaces.map((i) => i.name)]), b: graph.blocks.map((b) => b.cidr),
    e: visibleEdges(graph, hiddenTags, showWeak).map((e) => e.id), hiddenTags, showWeak,
  }), [graph, hiddenTags, showWeak])

  // re-layout only when the structure changes; data-only updates patch nodes in place
  useEffect(() => {
    let cancel = false
    layout(graph, hiddenTags, showWeak).then(({ nodes: n, edges: e }) => {
      if (cancel) return
      const { positions } = useStore.getState()
      setNodes(n.map((x) => (positions[x.id] ? { ...x, position: positions[x.id] } : x)))
      setRaw(e)
      setTimeout(() => rf.fitView({ padding: 0.15, duration: 300 }), 50)
    })
    return () => { cancel = true }
  }, [structure, layoutNonce])

  useEffect(() => {
    const tagColor = Object.fromEntries(graph.tags.map((t) => [t.name, t.color]))
    const bmap = Object.fromEntries(graph.blocks.map((b) => [nodeId.block(b.cidr), b]))
    const crit = new Set(raw.filter((e) => e.severity === 'critical' || e.severity === 'high').map((e) => nodeId.block(e.block24)))
    setNodes((ns) => ns.map((n) => (n.type === 'block' && bmap[n.id]
      ? { ...n, data: { ...bmap[n.id], color: tagColor[bmap[n.id].tag] || '#8b8d98', violation: crit.has(n.id) } } : n)))
    const edgeData = Object.fromEntries(graph.edges.map((e) => [e.id, e]))
    setRaw((r) => r.map((e) => edgeData[e.id] || e))
  }, [graph])

  useEffect(() => { setEdges(raw.map((e) => toFlowEdge(e, selectedEdge?.id))) }, [raw, selectedEdge])

  const onNodeDragStop = (_, node, dragged) => {
    const next = { ...useStore.getState().positions }
    ;(dragged?.length ? dragged : [node]).forEach((n) => { next[n.id] = n.position })
    savePositions(next)
  }

  return (
    <div className="graph" id="graph">
      <ReactFlow nodes={nodes} edges={edges} onNodesChange={onNodesChange} onEdgesChange={onEdgesChange}
        nodeTypes={nodeTypes} onNodeDragStop={onNodeDragStop} minZoom={0.1} proOptions={{ hideAttribution: true }}
        onEdgeClick={(_, e) => useStore.setState({ selectedEdge: e.data })} onPaneClick={() => useStore.setState({ selectedEdge: null })}
        colorMode="dark">
        <Background gap={24} color="#24262e" />
        <Controls showInteractive={false} />
        <MiniMap pannable zoomable nodeColor={(n) => (n.type === 'block' ? n.data.color : n.type === 'iface' ? '#9aa0b0' : 'transparent')} />
      </ReactFlow>
      {!graph.machines.length && !graph.blocks.length && (
        <div className="empty">Add a test machine and a scope on the left. Interfaces appear on top, tagged /24 networks below; arrows mean strong evidence of reachability.</div>
      )}
    </div>
  )
}
