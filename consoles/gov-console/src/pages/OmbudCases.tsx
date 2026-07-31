import { useCallback, useEffect, useState } from 'react'
import { api, fmtKobo, Session } from '../api'
import { Badge, Card, Empty, ErrorBox, PageTitle, SkeletonRows } from '../components/ui'
import MoneyInput from '../components/MoneyInput'

interface OmbudCase {
  id: string
  appellant_pseudo_tin: string
  authority: string
  tax_type: string
  disputed_amount_kobo: number
  grounds: string
  state: string
  ack_deadline: string
  decide_deadline: string
  deposit?: { hold_id: string; amount_kobo: number; status: string; mode: string }
  documents?: Array<{ doc_id: string; title: string; privileged: boolean }>
}

interface Gate {
  active: boolean
  mode: string
}

const NEXT: Record<string, { action: string; label: string }> = {
  received: { action: 'acknowledge', label: 'Acknowledge' },
  acknowledged: { action: 'review', label: 'Start review' },
  under_review: { action: 'schedule_hearing', label: 'Schedule hearing' },
  hearing: { action: 'decide', label: 'Decide' },
  decided: { action: 'close', label: 'Close' },
}

export default function OmbudCases({ session }: { session: Session }) {
  const [cases, setCases] = useState<OmbudCase[]>([])
  const [gate, setGate] = useState<Gate | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [form, setForm] = useState({ appellant_pseudo_tin: '', authority: 'NRS', tax_type: 'CIT', grounds: '' })
  const [amountKobo, setAmountKobo] = useState<number | null>(null)
  const [loading, setLoading] = useState(true)
  const [msg, setMsg] = useState<string | null>(null)

  const load = useCallback(async () => {
    try {
      const data = await api<{ cases: OmbudCase[] }>('ombud', '/v1/cases', { session })
      setCases(data.cases || [])
      const g = await api<Gate>('ombud', '/v1/gate', { session })
      setGate(g)
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

  const act = async (path: string, body: unknown) => {
    setMsg(null)
    try {
      await api('ombud', path, { method: 'POST', session, body })
      await load()
    } catch (e) {
      setError((e as Error).message)
    }
  }

  const intake = async () => {
    setMsg(null)
    try {
      const c = await api<OmbudCase>('ombud', '/v1/cases', {
        method: 'POST',
        session,
        body: {
          appellant_pseudo_tin: form.appellant_pseudo_tin,
          authority: form.authority,
          tax_type: form.tax_type,
          disputed_amount_kobo: amountKobo ?? 0,
          grounds: form.grounds,
        },
      })
      setMsg(`${c.id} received; ack deadline ${new Date(c.ack_deadline).toLocaleDateString()}`)
      setForm({ ...form, appellant_pseudo_tin: '', grounds: '' })
      setAmountKobo(null)
      await load()
    } catch (e) {
      setError((e as Error).message)
    }
  }

  return (
    <div>
      <PageTitle
        title="Ombud registry console"
        sub="Case registry, 20% deposit holds (ledger 500), WORM evidence packs, privilege-filtered search."
      />
      <div
        className={`mb-4 rounded-lg border px-4 py-2 text-sm ${
          gate?.active
            ? 'border-success-strong/40 bg-success text-success-on'
            : 'border-warning-strong/40 bg-warning text-warning-on'
        }`}
      >
        Activation gate ombud.rules_active: {gate ? (gate.active ? 'ACTIVE' : 'OFF') : '…'} ({gate?.mode})
      </div>
      <ErrorBox error={error} />
      <Card className="mb-4">
        <h2 className="mb-2 text-sm font-semibold text-stone-900">Intake (clerk)</h2>
        <div className="grid grid-cols-2 gap-2 md:grid-cols-5">
          <input
            aria-label="Appellant pseudonymised TIN"
            className="input font-mono"
            placeholder="appellant ptin_…"
            value={form.appellant_pseudo_tin}
            onChange={(e) => setForm({ ...form, appellant_pseudo_tin: e.target.value })}
          />
          <select aria-label="Authority" className="input" value={form.authority} onChange={(e) => setForm({ ...form, authority: e.target.value })}>
            {['NRS', 'NG-LA', 'NG-FC', 'NG-KN'].map((a) => (
              <option key={a}>{a}</option>
            ))}
          </select>
          <select aria-label="Tax type" className="input" value={form.tax_type} onChange={(e) => setForm({ ...form, tax_type: e.target.value })}>
            {['CIT', 'VAT', 'PIT', 'WHT'].map((t) => (
              <option key={t}>{t}</option>
            ))}
          </select>
          <div aria-label="Disputed amount">
            <MoneyInput id="ombud-amount" valueKobo={amountKobo} onChangeKobo={setAmountKobo} />
          </div>
          <input
            aria-label="Grounds"
            className="input"
            placeholder="grounds"
            value={form.grounds}
            onChange={(e) => setForm({ ...form, grounds: e.target.value })}
          />
        </div>
        <div className="mt-2 flex items-center gap-3">
          <button
            className="btn btn-primary"
            disabled={!form.appellant_pseudo_tin.startsWith('ptin_') || amountKobo == null || !form.grounds}
            onClick={intake}
          >
            Intake case
          </button>
          {msg && <span aria-live="polite" className="text-sm text-success-strong">{msg}</span>}
        </div>
      </Card>
      <Card>
        {loading ? (
          <div aria-busy="true" aria-label="Loading cases"><SkeletonRows rows={5} /></div>
        ) : cases.length === 0 ? (
          <Empty title="No cases yet">Intake a case above to open the registry.</Empty>
        ) : (
          <table className="w-full">
            <thead>
              <tr className="border-b border-neutral-200">
                <th scope="col" className="th">Case</th>
                <th scope="col" className="th">Tax</th>
                <th scope="col" className="th">Disputed</th>
                <th scope="col" className="th">State</th>
                <th scope="col" className="th">Decide by</th>
                <th scope="col" className="th">Deposit</th>
                <th scope="col" className="th">Actions</th>
              </tr>
            </thead>
            <tbody>
              {cases.map((c) => (
                <tr key={c.id} className="border-b border-neutral-100 hover:bg-neutral-50">
                  <td className="td font-mono text-xs">{c.id}</td>
                  <td className="td">{c.tax_type}</td>
                  <td className="td">{fmtKobo(c.disputed_amount_kobo)}</td>
                  <td className="td">
                    <Badge tone={c.state === 'closed' ? 'neutral' : c.state === 'decided' ? 'green' : 'amber'}>
                      {c.state}
                    </Badge>
                  </td>
                  <td className="td text-xs text-stone-600">{new Date(c.decide_deadline).toLocaleDateString()}</td>
                  <td className="td text-xs">
                    {c.deposit ? (
                      <span>
                        {fmtKobo(c.deposit.amount_kobo)}{' '}
                        <Badge tone={c.deposit.status === 'held' ? 'amber' : 'green'}>{c.deposit.status}</Badge>
                      </span>
                    ) : (
                      '—'
                    )}
                  </td>
                  <td className="td">
                    <div className="flex flex-wrap gap-1">
                      {NEXT[c.state] && (
                        <button
                          className="btn"
                          onClick={() =>
                            act(`/v1/cases/${c.id}/transition`, {
                              action: NEXT[c.state].action,
                              detail: NEXT[c.state].action === 'decide' ? 'decision recorded from console' : '',
                            })
                          }
                        >
                          {NEXT[c.state].label}
                        </button>
                      )}
                      {!c.deposit && (
                        <button className="btn" onClick={() => act(`/v1/cases/${c.id}/deposit`, {})}>
                          20% deposit
                        </button>
                      )}
                      {c.deposit?.status === 'held' && (
                        <>
                          <button className="btn" onClick={() => act(`/v1/cases/${c.id}/deposit/release`, {})}>
                            Release
                          </button>
                          <button className="btn" onClick={() => act(`/v1/cases/${c.id}/deposit/settle`, {})}>
                            Settle
                          </button>
                        </>
                      )}
                      <button className="btn" onClick={() => act(`/v1/cases/${c.id}/evidence-pack`, {})}>
                        Evidence pack
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
    </div>
  )
}
