import { useEffect } from 'react'
import { ReactFlowProvider } from '@xyflow/react'
import { connectWS, fmtDur } from './api'
import { useStore } from './store'
import Sidebar from './Sidebar'
import Graph from './Graph'
import Toolbar from './Toolbar'
import EdgePanel from './EdgePanel'
import JobDrawer from './JobDrawer'

export default function App() {
  const { loadState, loadGraph, loadPositions, loadGraphSoon, upsertJob, selectedEdge, pendingRun, run, toast } = useStore()

  useEffect(() => {
    const init = () => loadPositions().then(() => Promise.all([loadState(), loadGraph()])).catch((e) => useStore.getState().notify(e.message))
    init()
    connectWS({
      onOpen: init, // resync after reconnect (queue survives reloads and restarts)
      job: (m) => upsertJob(m.job),
      graph: () => loadGraphSoon(),
    })
  }, [])

  return (
    <ReactFlowProvider>
      <div className="app">
        <Sidebar />
        <main className="main">
          <Toolbar />
          {pendingRun && (
            <div className="confirmbar">
              <b>Long scan:</b> {pendingRun.jobs} jobs, estimated ~{fmtDur(pendingRun.estimate)} at the chosen -T template.
              <button className="danger" onClick={() => run(pendingRun.specs, true)}>Queue anyway</button>
              <button onClick={() => useStore.setState({ pendingRun: null })}>Cancel</button>
            </div>
          )}
          <div className="center">
            <Graph />
            {selectedEdge && <EdgePanel />}
          </div>
          <JobDrawer />
        </main>
        {toast && <div className={`toast ${toast.kind}`} onClick={() => useStore.setState({ toast: null })}>{toast.msg}</div>}
      </div>
    </ReactFlowProvider>
  )
}
