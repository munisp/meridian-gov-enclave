import { useCallback, useEffect, useState } from 'react'
import { api, Session, short } from '../api'
import { Badge, Card, Empty, ErrorBox, PageTitle } from '../components/ui'

interface EOI {
  id: string
  requester_id: string
  responder_id: string
  subject_pseudo_tin: string
  purpose: string
  status: string
  request: string
  response?: string
  created_at: string
  gateway_receipt?: string
}

export default function EoiInbox({ session }: { session: Session }) {
  const [items, setItems] = useState<EOI[]>([])
  const [banner, setBanner] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [form, setForm] = useState({ responder_id: 'NG-KN', subject_pseudo_tin: '', purpose: '', request: '' })
  const [msg, setMsg] = useState<string | null>(null)

  const load = useCallback(async () => {
    try {
      const data = await api<{ items: EOI[]; visibility_banner: string }>('jrb', '/v1/eoi', { session })
      setItems(data.items || [])
      setBanner(data.visibility_banner)
      setError(null)
    } catch (e) {
      setError((e as Error).message)
    }
  }, [session])

  useEffect(() => {
    load()
  }, [load])

  const create = async () => {
    setMsg(null)
    try {
      const res = await api<{ eoi: EOI; gateway_receipt: { mode: string } }>('jrb', '/v1/eoi', {
        method: 'POST',
        session,
        body: { ...form, requester_id: session.authorityId },
      })
      setMsg(`${res.eoi.id} sent via ${res.gateway_receipt.mode}`)
      setForm({ ...form, subject_pseudo_tin: '', purpose: '', request: '' })
      await load()
    } catch (e) {
      setError((e as Error).message)
    }
  }

  return (
    <div>
      <PageTitle title="EOI inbox" sub="Exchange of information between authorities (F6: enclave-internal)." />
      <div className="mb-4 rounded-lg border border-moss-500/40 bg-moss-100 px-4 py-2 text-sm text-moss-700">
        {banner || 'Four-party visibility: requester + responder + secretariat only.'}
      </div>
      <ErrorBox error={error} />
      <Card className="mb-4">
        <h2 className="mb-2 text-sm font-semibold text-sand-700">New exchange (as {session.authorityId})</h2>
        <div className="grid grid-cols-2 gap-2">
          <select
            className="input"
            value={form.responder_id}
            onChange={(e) => setForm({ ...form, responder_id: e.target.value })}
          >
            {['NRS', 'NG-LA', 'NG-FC', 'NG-KN', 'NG-RI']
              .filter((x) => x !== session.authorityId)
              .map((x) => (
                <option key={x}>{x}</option>
              ))}
          </select>
          <input
            className="input font-mono"
            placeholder="subject ptin_…"
            value={form.subject_pseudo_tin}
            onChange={(e) => setForm({ ...form, subject_pseudo_tin: e.target.value })}
          />
          <input
            className="input"
            placeholder="purpose (e.g. VAT audit)"
            value={form.purpose}
            onChange={(e) => setForm({ ...form, purpose: e.target.value })}
          />
          <input
            className="input"
            placeholder="request summary"
            value={form.request}
            onChange={(e) => setForm({ ...form, request: e.target.value })}
          />
        </div>
        <div className="mt-2 flex items-center gap-3">
          <button
            className="btn btn-primary"
            disabled={!form.subject_pseudo_tin.startsWith('ptin_') || !form.purpose}
            onClick={create}
          >
            Send via enclave-gateway (F6)
          </button>
          {msg && <span className="text-sm text-moss-600">{msg}</span>}
        </div>
      </Card>
      <Card>
        {items.length === 0 ? (
          <Empty>Nothing visible to this authority.</Empty>
        ) : (
          <table className="w-full">
            <thead>
              <tr className="border-b border-sand-200">
                <th className="th">EOI</th>
                <th className="th">Requester → Responder</th>
                <th className="th">Subject</th>
                <th className="th">Purpose</th>
                <th className="th">Status</th>
                <th className="th">WORM receipt</th>
              </tr>
            </thead>
            <tbody>
              {items.map((e) => (
                <tr key={e.id} className="border-b border-sand-100 hover:bg-sand-50">
                  <td className="td font-mono text-xs">{e.id}</td>
                  <td className="td text-xs">
                    {e.requester_id} → {e.responder_id}
                  </td>
                  <td className="td font-mono text-xs">{short(e.subject_pseudo_tin, 16)}</td>
                  <td className="td text-xs">{e.purpose}</td>
                  <td className="td">
                    <Badge tone={e.status === 'answered' ? 'green' : 'amber'}>{e.status}</Badge>
                  </td>
                  <td className="td font-mono text-xs text-sand-500">{short(e.gateway_receipt || '', 18)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
    </div>
  )
}
