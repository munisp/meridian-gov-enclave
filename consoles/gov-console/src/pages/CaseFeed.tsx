import { useCallback, useEffect, useState } from 'react'
import { api, Session, short } from '../api'
import { Badge, bandTone, Card, Empty, ErrorBox, PageTitle } from '../components/ui'

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

  const load = useCallback(async () => {
    try {
      const data = await api<{ items: FeedItem[] }>(
        'analytics',
        `/v1/cases/feed${band ? `?band=${band}` : ''}`,
        { session },
      )
      setItems(data.items || [])
      setError(null)
    } catch (e) {
      setError((e as Error).message)
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
        <select className="input w-44" value={band} onChange={(e) => setBand(e.target.value)}>
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
        {items.length === 0 ? (
          <Empty>No cases — the feed populates when scores cross the threshold.</Empty>
        ) : (
          <table className="w-full">
            <thead>
              <tr className="border-b border-sand-200">
                <th className="th">Case</th>
                <th className="th">Type</th>
                <th className="th">Score</th>
                <th className="th">Band</th>
                <th className="th">Status</th>
                <th className="th">Time</th>
              </tr>
            </thead>
            <tbody>
              {items.map((it) => (
                <tr key={it.id} className="border-b border-sand-100 hover:bg-sand-50">
                  <td className="td font-mono text-xs">{short(it.id, 16)}</td>
                  <td className="td text-xs">{it.data.case_type}</td>
                  <td className="td font-semibold">{it.data.score}</td>
                  <td className="td">
                    <Badge tone={bandTone(it.data.band)}>{it.data.band}</Badge>
                  </td>
                  <td className="td">
                    <Badge tone="neutral">{it.data.status}</Badge>
                  </td>
                  <td className="td text-xs text-sand-500">{new Date(it.time).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
    </div>
  )
}
