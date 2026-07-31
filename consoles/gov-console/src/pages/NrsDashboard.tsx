import { useCallback, useEffect, useState } from 'react'
import { api, Session, short } from '../api'
import { Badge, bandTone, Card, Empty, ErrorBox, PageTitle, SkeletonRows } from '../components/ui'

interface ScoreRow {
  score_id: string
  pseudo_tin: string
  score: number
  band: string
  model_id: string
  model_version: string
  rule_pack_version: string
  scored_at: string
}

interface Explanation {
  model: { id: string; version: string }
  rule_pack_version: string
  score: number
  band: string
  contributions: Array<{
    rule_id: string
    narrate: string
    points: number
    evidence: { feature: string; feature_row: Record<string, unknown> }
  }>
  generated_at: string
}

export default function NrsDashboard({ session }: { session: Session }) {
  const [scores, setScores] = useState<ScoreRow[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [selected, setSelected] = useState<string | null>(null)
  const [expl, setExpl] = useState<Explanation | null>(null)
  const [msg, setMsg] = useState<string | null>(null)

  const load = useCallback(async () => {
    try {
      const data = await api<{ scores: ScoreRow[] }>('analytics', '/v1/scores', { session })
      setScores(data.scores || [])
      setError(null)
      setLoading(false)
    } catch (e) {
      setError((e as Error).message)
      setLoading(false)
    }
  }, [session])

  useEffect(() => {
    load()
  }, [load])

  const drill = async (pseudo: string) => {
    setSelected(pseudo)
    setExpl(null)
    try {
      const data = await api<{ explanation: Explanation }>(
        'analytics',
        `/v1/scores/${pseudo}/explanation`,
        { session },
      )
      setExpl(data.explanation)
    } catch (e) {
      setError((e as Error).message)
    }
  }

  const runDaily = async () => {
    setMsg(null)
    try {
      const run = await api<{ status: string; run_id: string }>(
        'analytics',
        '/v1/workflows/wf-daily-scoring/run',
        { method: 'POST', session, body: {} },
      )
      setMsg(`wf-daily-scoring ${run.status} (${run.run_id})`)
      await load()
    } catch (e) {
      setError((e as Error).message)
    }
  }

  const bands = scores.reduce<Record<string, number>>((acc, s) => {
    acc[s.band] = (acc[s.band] || 0) + 1
    return acc
  }, {})

  return (
    <div>
      <PageTitle
        title="NRS scoring dashboard"
        sub="Transparent rule+score model — every score carries an auditable explanation payload. Pseudonymised subjects only."
      />
      <ErrorBox error={error} />
      <div className="mb-4 flex flex-wrap items-center gap-3">
        <button className="btn btn-primary" onClick={runDaily}>
          Run wf-daily-scoring
        </button>
        {msg && <span aria-live="polite" className="text-sm text-success-strong">{msg}</span>}
        <div className="ml-auto flex gap-2">
          {(['high', 'medium', 'low'] as const).map((b) => (
            <Badge key={b} tone={bandTone(b)}>
              {b}: {bands[b] || 0}
            </Badge>
          ))}
        </div>
      </div>
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        <Card>
          <h2 className="mb-3 text-sm font-semibold text-stone-900">Latest scores</h2>
          {loading ? (
            <div aria-busy="true" aria-label="Loading scores"><SkeletonRows /></div>
          ) : scores.length === 0 ? (
            <Empty title="No scores yet">Ingest data and run wf-daily-scoring.</Empty>
          ) : (
            <table className="w-full">
              <thead>
                <tr className="border-b border-neutral-200">
                  <th scope="col" className="th">Subject</th>
                  <th scope="col" className="th">Score</th>
                  <th scope="col" className="th">Band</th>
                  <th scope="col" className="th">Model</th>
                  <th scope="col" className="th"></th>
                </tr>
              </thead>
              <tbody>
                {scores.map((s) => (
                  <tr key={s.score_id} className="border-b border-neutral-100 hover:bg-neutral-50">
                    <td className="td font-mono text-xs">{short(s.pseudo_tin, 18)}</td>
                    <td className="td font-semibold">{s.score}</td>
                    <td className="td">
                      <Badge tone={bandTone(s.band)}>{s.band}</Badge>
                    </td>
                    <td className="td text-xs text-stone-600">
                      {s.model_id}@{s.model_version}
                    </td>
                    <td className="td">
                      <button className="btn" onClick={() => drill(s.pseudo_tin)}>
                        Explain
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>
        <Card>
          <h2 className="mb-3 text-sm font-semibold text-stone-900">Explanation drill-down</h2>
          {!selected ? (
            <Empty title="No score selected">Select “Explain” on a score to see the full audit trail.</Empty>
          ) : !expl ? (
            <div aria-busy="true" aria-label="Loading explanation"><SkeletonRows rows={3} /></div>
          ) : (
            <div>
              <div className="mb-3 flex items-center gap-3">
                <span className="font-mono text-xs">{short(selected, 22)}</span>
                <Badge tone={bandTone(expl.band)}>{expl.band}</Badge>
                <span className="text-lg font-bold">{expl.score}</span>
              </div>
              <div className="mb-3 text-xs text-stone-600">
                model {expl.model.id}@{expl.model.version} · pack {expl.rule_pack_version} ·{' '}
                {new Date(expl.generated_at).toLocaleString()}
              </div>
              <ul className="space-y-3">
                {expl.contributions.map((c) => (
                  <li key={c.rule_id} className="rounded-lg border border-neutral-200 p-3">
                    <div className="flex items-center justify-between">
                      <span className="font-mono text-xs text-brand-700">{c.rule_id}</span>
                      <span className="chip bg-info text-info-on">+{c.points}</span>
                    </div>
                    <p className="mt-1 text-sm text-stone-900">{c.narrate}</p>
                    <pre className="mt-2 overflow-x-auto rounded bg-neutral-100 p-2 text-xs text-stone-600">
                      {JSON.stringify(c.evidence.feature_row, null, 2)}
                    </pre>
                  </li>
                ))}
                {expl.contributions.length === 0 && (
                  <Empty title="No rule fired">Baseline score.</Empty>
                )}
              </ul>
            </div>
          )}
        </Card>
      </div>
    </div>
  )
}
