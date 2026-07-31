import { useCallback, useEffect, useState } from 'react'
import { api, fmtKobo, Session, short } from '../api'
import { Badge, Card, Empty, ErrorBox, PageTitle, SkeletonRows } from '../components/ui'

interface FeedState {
  state_code: string
  consumption_portion_kobo: number
  equality_portion_kobo: number
  derivation_portion_kobo: number
  total_kobo: number
}

interface SignedDoc {
  feed: {
    feed_id: string
    period: string
    pool_kobo: number
    formula: { place_of_consumption_weight_bps: number; pack_ref?: string; PackRef?: string }
    states: FeedState[]
    built_at: string
  }
  signature: string
  public_key: string
}

export default function AttributionFeeds({ session }: { session: Session }) {
  const [doc, setDoc] = useState<SignedDoc | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [msg, setMsg] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)

  const load = useCallback(async () => {
    try {
      // Via the audited gateway (F7): signature verified before serving.
      const data = await api<SignedDoc>('gateway', '/flows/f7/attribution-feeds/NG-LA', { session })
      setDoc(data)
      setError(null)
      setLoading(false)
    } catch (e) {
      setError((e as Error).message)
      setDoc(null)
      setLoading(false)
    }
  }, [session])

  useEffect(() => {
    load()
  }, [load])

  const publish = async () => {
    setMsg(null)
    try {
      const run = await api<{ status: string }>('jrb', '/v1/workflows/wf-jrb-attribution-publish/run', {
        method: 'POST',
        session,
        body: {},
      })
      setMsg(`wf-jrb-attribution-publish ${run.status}`)
      await load()
    } catch (e) {
      setError((e as Error).message)
    }
  }

  const total = doc?.feed.states.reduce((a, s) => a + s.total_kobo, 0) || 0

  return (
    <div>
      <PageTitle
        title="Attribution feeds"
        sub="NTAA VAT attribution: 30% place-of-consumption. Feeds are ed25519-signed by JRB and served via gateway F7 after signature verification."
      />
      <ErrorBox error={error} />
      <div className="mb-4 flex items-center gap-3">
        <button className="btn btn-primary" onClick={publish}>
          Publish feed (wf-jrb-attribution-publish)
        </button>
        <button className="btn" onClick={load}>
          Reload via F7
        </button>
        {msg && <span aria-live="polite" className="text-sm text-success-strong">{msg}</span>}
      </div>
      {loading ? (
        <div aria-busy="true" aria-label="Loading signed feed"><SkeletonRows rows={6} /></div>
      ) : !doc ? (
        <Empty title="No signed feed yet">Publish one to see the attribution breakdown.</Empty>
      ) : (
        <Card>
          <div className="mb-3 flex flex-wrap items-center gap-3 text-sm">
            <span className="font-semibold">{doc.feed.feed_id}</span>
            <Badge tone="neutral">period {doc.feed.period}</Badge>
            <Badge tone="green">ed25519 verified by gateway</Badge>
            <span className="text-xs text-stone-600">sig {short(doc.signature, 24)}</span>
          </div>
          <div className="mb-3 text-sm text-stone-600">
            Pool <span className="font-semibold">{fmtKobo(doc.feed.pool_kobo)}</span> · distributed{' '}
            <span className="font-semibold">{fmtKobo(total)}</span> · place-of-consumption weight{' '}
            {doc.feed.formula.place_of_consumption_weight_bps / 100}%
          </div>
          <table className="w-full">
            <thead>
              <tr className="border-b border-neutral-200">
                <th scope="col" className="th">State</th>
                <th scope="col" className="th">Consumption (30%)</th>
                <th scope="col" className="th">Equality</th>
                <th scope="col" className="th">Derivation</th>
                <th scope="col" className="th">Total</th>
              </tr>
            </thead>
            <tbody>
              {doc.feed.states.map((s) => (
                <tr key={s.state_code} className="border-b border-neutral-100 hover:bg-neutral-50">
                  <td className="td font-mono text-xs">{s.state_code}</td>
                  <td className="td">{fmtKobo(s.consumption_portion_kobo)}</td>
                  <td className="td">{fmtKobo(s.equality_portion_kobo)}</td>
                  <td className="td">{fmtKobo(s.derivation_portion_kobo)}</td>
                  <td className="td font-semibold">{fmtKobo(s.total_kobo)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      )}
    </div>
  )
}
