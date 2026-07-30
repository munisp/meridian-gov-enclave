import { useCallback, useEffect, useState } from 'react'
import { api, fmtKobo, Session, short } from '../api'
import { Badge, Card, Empty, ErrorBox, PageTitle } from '../components/ui'

interface LandingCost {
  declaration_id: string
  pseudo_tin: string
  hs_code: string
  port_code: string
  customs_value_kobo: number
  duty_kobo: number
  landing_cost_kobo: number
  import_vat_due_kobo: number
  vat_rate_bps: number
  tin_status: string
}

interface SilverRow {
  declaration_id: string
  tin_status: string
  importer_entity_id: string | null
  tin_graph_mode: string
}

export default function NswDeclarations({ session }: { session: Session }) {
  const [rows, setRows] = useState<LandingCost[]>([])
  const [silver, setSilver] = useState<SilverRow[]>([])
  const [error, setError] = useState<string | null>(null)
  const [paste, setPaste] = useState('')
  const [msg, setMsg] = useState<string | null>(null)

  const load = useCallback(async () => {
    try {
      const gold = await api<{ rows: LandingCost[] }>(
        'analytics',
        '/v1/lakehouse/gold/import_vat_landing_cost',
        { session },
      )
      setRows(gold.rows || [])
      const sv = await api<{ rows: SilverRow[] }>(
        'analytics',
        '/v1/lakehouse/silver/customs_declarations',
        { session },
      )
      setSilver(sv.rows || [])
      setError(null)
    } catch (e) {
      setError((e as Error).message)
    }
  }, [session])

  useEffect(() => {
    load()
  }, [load])

  const submit = async () => {
    setMsg(null)
    try {
      const records = JSON.parse(paste)
      const res = await api<{ accepted: number; rejected: number; reconciliation: Record<string, number> }>(
        'analytics',
        '/ingest/nsw/declarations',
        { method: 'POST', session, body: { records: Array.isArray(records) ? records : [records] } },
      )
      setMsg(`accepted ${res.accepted}, rejected ${res.rejected} · reconciliation ${JSON.stringify(res.reconciliation)}`)
      setPaste('')
      await load()
    } catch (e) {
      setError((e as Error).message)
    }
  }

  const statusOf = (id: string) => silver.find((s) => s.declaration_id === id)

  return (
    <div>
      <PageTitle
        title="NSW declarations (T15)"
        sub="Customs declarations → customs_declarations store with importer-TIN reconciliation → import-VAT landing-cost product (pseudonymised gold)."
      />
      <ErrorBox error={error} />
      <Card className="mb-4">
        <h2 className="mb-2 text-sm font-semibold text-sand-700">Ingest declarations (JSON array)</h2>
        <textarea
          className="input mb-2 h-28 font-mono text-xs"
          placeholder='[{"declaration_id":"NSW-100","importer_tin":"12345678-0001","hs_code":"8703.22","customs_value_kobo":500000000,"duty_kobo":100000000,"port_code":"NGAPP","declared_at":"2026-07-20T10:00:00Z"}]'
          value={paste}
          onChange={(e) => setPaste(e.target.value)}
        />
        <div className="flex items-center gap-3">
          <button className="btn btn-primary" onClick={submit} disabled={!paste.trim()}>
            POST /ingest/nsw/declarations
          </button>
          {msg && <span className="text-sm text-moss-600">{msg}</span>}
        </div>
      </Card>
      <Card>
        <h2 className="mb-3 text-sm font-semibold text-sand-700">Import-VAT landing-cost product (gold)</h2>
        {rows.length === 0 ? (
          <Empty>No declarations ingested yet.</Empty>
        ) : (
          <table className="w-full">
            <thead>
              <tr className="border-b border-sand-200">
                <th className="th">Declaration</th>
                <th className="th">Importer</th>
                <th className="th">TIN status</th>
                <th className="th">HS / Port</th>
                <th className="th">Customs value</th>
                <th className="th">Landing cost</th>
                <th className="th">Import VAT (7.5%)</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.declaration_id} className="border-b border-sand-100 hover:bg-sand-50">
                  <td className="td font-mono text-xs">{r.declaration_id}</td>
                  <td className="td font-mono text-xs">{short(r.pseudo_tin, 16)}</td>
                  <td className="td">
                    <Badge tone={r.tin_status === 'verified' ? 'green' : 'amber'}>
                      {r.tin_status}
                      {statusOf(r.declaration_id)?.tin_graph_mode === 'local-fallback' ? ' ·local' : ''}
                    </Badge>
                  </td>
                  <td className="td text-xs">
                    {r.hs_code} · {r.port_code}
                  </td>
                  <td className="td">{fmtKobo(r.customs_value_kobo)}</td>
                  <td className="td font-semibold">{fmtKobo(r.landing_cost_kobo)}</td>
                  <td className="td">{fmtKobo(r.import_vat_due_kobo)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
    </div>
  )
}
