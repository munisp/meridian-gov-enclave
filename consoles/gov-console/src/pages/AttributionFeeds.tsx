import { useCallback, useEffect, useState } from 'react'
import { api, fmtKobo, Session, short } from '../api'
import { Badge, Card, Empty, ErrorBox, PageTitle } from '../components/ui'

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

  const load = useCallback(async () => {
    try {
      // Via the audited gateway (F7): signature verified before serving.
      const data = await api<SignedDoc>('gateway', '/flows/f7/attribution-feeds/NG-LA', { session })
      setDoc(data)
      setError(null)
    } catch (e) {
      setError((e as Error).message)
      setDoc(null)
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
        {msg && <span className="text-sm text-moss-600">{msg}</span>}
      </div>
      {!doc ? (
        <Empty>No signed feed yet — publish one.</Empty>
      ) : (
        <Card>
          <div className="mb-3 flex flex-wrap items-center gap-3 text-sm">
            <span className="font-semibold">{doc.feed.feed_id}</span>
            <Badge tone="neutral">period {doc.feed.period}</Badge>
            <Badge tone="green">ed25519 verified by gateway</Badge>
            <span className="text-xs text-sand-500">sig {short(doc.signature, 24)}</span>
          </div>
          <div className="mb-3 text-sm text-sand-600">
            Pool <span className="font-semibold">{fmtKobo(doc.feed.pool_kobo)}</span> · distributed{' '}
            <span className="font-semibold">{fmtKobo(total)}</span> · place-of-consumption weight{' '}
            {doc.feed.formula.place_of_consumption_weight_bps / 100}%
          </div>
          <table className="w-full">
            <thead>
              <tr className="border-b border-sand-200">
                <th className="th">State</th>
                <th className="th">Consumption (30%)</th>
                <th className="th">Equality</th>
                <th className="th">Derivation</th>
                <th className="th">Total</th>
              </tr>
            </thead>
            <tbody>
              {doc.feed.states.map((s) => (
                <tr key={s.state_code} className="border-b border-sand-100 hover:bg-sand-50">
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
