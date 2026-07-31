import { useCallback, useEffect, useState } from 'react'
import { api, Session, short } from '../api'
import { Badge, bandTone, Card, Empty, ErrorBox, PageTitle, SkeletonRows } from '../components/ui'

interface FeedItem {
  id: string
  type: string
  source: string
  time: string
  rule_pack_version: string
  data: {
    case_type: string
    score: number
    band: string
    score_id: string
    status: string
    explanation_ref: string
    model: { id: string; version: string }
  }
}

export default function CaseFeed({ session }: { session: Session }) {
  const [items, setItems] = useState<FeedItem[]>([])
  const [band, setBand] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)

  const load = useCallback(async () => {
    try {
      const data = await api<{ items: FeedItem[] }>(
        'analytics',
        `/v1/cases/feed${band ? `?band=${band}` : ''}`,
        { session },
      )
      setItems(data.items || [])
      setError(null)
      setLoading(false)
    } catch (e) {
      setError((e as Error).message)
      setLoading(false)
    }
  }, [session, band])

  useEffect(() => {
    load()
  }, [load])

  return (
    <div>
      <PageTitle title="Case feed" sub="nrs.cases.feed.v1 envelope events for scores above the case threshold." />
      <ErrorBox error={error} />
      <div className="mb-4 flex items-center gap-2">
        <select aria-label="Filter by band" className="input w-44" value={band} onChange={(e) => setBand(e.target.value)}>
          <option value="">all bands</option>
          <option value="high">high</option>
          <option value="medium">medium</option>
          <option value="low">low</option>
        </select>
        <button className="btn" onClick={load}>
          Refresh
        </button>
      </div>
      <Card>
        {loading ? (
          <div aria-busy="true" aria-label="Loading cases"><SkeletonRows /></div>
        ) : items.length === 0 ? (
          <Empty title="No cases">The feed populates when scores cross the threshold.</Empty>
        ) : (
          <table className="w-full">
            <thead>
              <tr className="border-b border-neutral-200">
                <th scope="col" className="th">Case</th>
                <th scope="col" className="th">Type</th>
                <th scope="col" className="th">Score</th>
                <th scope="col" className="th">Band</th>
                <th scope="col" className="th">Status</th>
                <th scope="col" className="th">Time</th>
              </tr>
            </thead>
            <tbody>
              {items.map((it) => (
                <tr key={it.id} className="border-b border-neutral-100 hover:bg-neutral-50">
                  <td className="td font-mono text-xs">{short(it.id, 16)}</td>
                  <td className="td text-xs">{it.data.case_type}</td>
                  <td className="td font-semibold">{it.data.score}</td>
                  <td className="td">
                    <Badge tone={bandTone(it.data.band)}>{it.data.band}</Badge>
                  </td>
                  <td className="td">
                    <Badge tone="neutral">{it.data.status}</Badge>
                  </td>
                  <td className="td text-xs text-stone-600">{new Date(it.time).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
    </div>
  )
}
