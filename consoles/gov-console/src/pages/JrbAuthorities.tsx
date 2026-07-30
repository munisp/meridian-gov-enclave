import { useCallback, useEffect, useState } from 'react'
import { api, Session, short } from '../api'
import { Badge, Card, Empty, ErrorBox, PageTitle } from '../components/ui'

interface Authority {
  id: string
  kind: string
  name: string
  status: string
  cert_fingerprint?: string
  onboarded_at?: string
}

export default function JrbAuthorities({ session }: { session: Session }) {
  const [rows, setRows] = useState<Authority[]>([])
  const [error, setError] = useState<string | null>(null)
  const [filter, setFilter] = useState('')

  const load = useCallback(async () => {
    try {
      const data = await api<{ authorities: Authority[] }>('jrb', '/v1/authorities', { session })
      setRows(data.authorities || [])
      setError(null)
    } catch (e) {
      setError((e as Error).message)
    }
  }, [session])

  useEffect(() => {
    load()
  }, [load])

  const shown = rows.filter(
    (a) => !filter || a.name.toLowerCase().includes(filter.toLowerCase()) || a.id.includes(filter.toUpperCase()),
  )

  return (
    <div>
      <PageTitle
        title="JRB authority registry"
        sub="NRS, JRB secretariat, 36 states + FCT. Dev onboarding: cert upload + SHA-256 fingerprint; prod: mTLS + OIDC."
      />
      <ErrorBox error={error} />
      <div className="mb-4 flex items-center gap-2">
        <input
          className="input w-64"
          placeholder="filter authorities…"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
        />
        <span className="text-sm text-sand-500">{shown.length} of {rows.length}</span>
      </div>
      <Card>
        {shown.length === 0 ? (
          <Empty>No authorities match.</Empty>
        ) : (
          <table className="w-full">
            <thead>
              <tr className="border-b border-sand-200">
                <th className="th">ID</th>
                <th className="th">Authority</th>
                <th className="th">Kind</th>
                <th className="th">Status</th>
                <th className="th">Cert fingerprint</th>
              </tr>
            </thead>
            <tbody>
              {shown.map((a) => (
                <tr key={a.id} className="border-b border-sand-100 hover:bg-sand-50">
                  <td className="td font-mono text-xs">{a.id}</td>
                  <td className="td">{a.name}</td>
                  <td className="td text-xs">{a.kind}</td>
                  <td className="td">
                    <Badge tone={a.status === 'active' ? 'green' : a.status === 'suspended' ? 'red' : 'amber'}>
                      {a.status}
                    </Badge>
                  </td>
                  <td className="td font-mono text-xs text-sand-500">
                    {a.cert_fingerprint ? short(a.cert_fingerprint, 20) : '—'}
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
