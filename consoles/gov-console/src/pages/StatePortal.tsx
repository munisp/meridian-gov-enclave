import { useCallback, useEffect, useState } from 'react'
import { api, fmtKobo, Session } from '../api'
import { Badge, Card, Empty, ErrorBox, PageTitle, SkeletonRows } from '../components/ui'

interface Filing {
  filing_id: string
  pseudo_tin: string
  tax_type: string
  period: string
  amount_kobo: number
  place_of_supply: string
  filed_at: string
}

interface FeedState {
  state_code: string
  consumption_portion_kobo: number
  equality_portion_kobo: number
  derivation_portion_kobo: number
  total_kobo: number
}

const STATES = [
  { code: 'NG-LA', name: 'Lagos (LIRS reference adapter)' },
  { code: 'NG-FC', name: 'FCT (FCT-IRS reference adapter)' },
  { code: 'NG-KN', name: 'Kano (generic adapter)' },
]

export default function StatePortal({ session }: { session: Session }) {
  const [state, setState] = useState('NG-LA')
  const [filings, setFilings] = useState<Filing[]>([])
  const [attribution, setAttribution] = useState<FeedState | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)

  const load = useCallback(async () => {
    setError(null)
    try {
      const f = await api<{ filings: Filing[] }>(
        'jrb',
        `/v1/adapters/${state}/pull-filings`,
        { method: 'POST', session, body: {} },
      )
      setFilings(f.filings || [])
      setLoading(false)
    } catch (e) {
      setError((e as Error).message)
      setLoading(false)
    }
    try {
      const doc = await api<{ feed: { states: FeedState[] } }>(
        'gateway',
        `/flows/f7/attribution-feeds/${state}`,
        { session },
      )
      setAttribution(doc.feed.states.find((s) => s.state_code === state) || null)
    } catch {
      setAttribution(null)
    }
  }, [session, state])

  useEffect(() => {
    load()
  }, [load])

  return (
    <div>
      <PageTitle
        title="State IRS portal view"
        sub="What a state authority sees: its filings feed (adapter) and its signed attribution row."
      />
      <ErrorBox error={error} />
      <div className="mb-4 flex items-center gap-2">
        <select aria-label="State adapter" className="input w-72" value={state} onChange={(e) => setState(e.target.value)}>
          {STATES.map((s) => (
            <option key={s.code} value={s.code}>
              {s.name}
            </option>
          ))}
        </select>
        <Badge tone="neutral">SIMULATED adapter data</Badge>
      </div>
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        <Card>
          <h2 className="mb-3 text-sm font-semibold text-stone-900">Filings feed · {state}</h2>
          {loading ? (
            <div aria-busy="true" aria-label="Loading filings"><SkeletonRows /></div>
          ) : filings.length === 0 ? (
            <Empty title="No filings">This adapter has returned no filings.</Empty>
          ) : (
            <table className="w-full">
              <thead>
                <tr className="border-b border-neutral-200">
                  <th scope="col" className="th">Filing</th>
                  <th scope="col" className="th">Tax</th>
                  <th scope="col" className="th">Place of supply</th>
                  <th scope="col" className="th">Amount</th>
                </tr>
              </thead>
              <tbody>
                {filings.map((f) => (
                  <tr key={f.filing_id} className="border-b border-neutral-100">
                    <td className="td font-mono text-xs">{f.filing_id}</td>
                    <td className="td">{f.tax_type}</td>
                    <td className="td text-xs">{f.place_of_supply}</td>
                    <td className="td font-semibold">{fmtKobo(f.amount_kobo)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>
        <Card>
          <h2 className="mb-3 text-sm font-semibold text-stone-900">Attribution · {state}</h2>
          {!attribution ? (
            <Empty title="No published feed">Publish from the JRB attribution console.</Empty>
          ) : (
            <dl className="space-y-2 text-sm">
              <div className="flex justify-between border-b border-neutral-100 pb-2">
                <dt className="text-stone-600">Place-of-consumption (30%)</dt>
                <dd className="font-semibold">{fmtKobo(attribution.consumption_portion_kobo)}</dd>
              </div>
              <div className="flex justify-between border-b border-neutral-100 pb-2">
                <dt className="text-stone-600">Equality</dt>
                <dd className="font-semibold">{fmtKobo(attribution.equality_portion_kobo)}</dd>
              </div>
              <div className="flex justify-between border-b border-neutral-100 pb-2">
                <dt className="text-stone-600">Derivation</dt>
                <dd className="font-semibold">{fmtKobo(attribution.derivation_portion_kobo)}</dd>
              </div>
              <div className="flex justify-between pt-1">
                <dt className="font-semibold">Total</dt>
                <dd className="text-lg font-bold text-brand-700">{fmtKobo(attribution.total_kobo)}</dd>
              </div>
            </dl>
          )}
        </Card>
      </div>
    </div>
  )
}
