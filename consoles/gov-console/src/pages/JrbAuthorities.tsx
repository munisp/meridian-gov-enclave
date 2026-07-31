import { useCallback, useEffect, useState } from 'react'
import { api, Session, short } from '../api'
import { Badge, Card, Empty, ErrorBox, PageTitle, SkeletonRows } from '../components/ui'

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
  const [loading, setLoading] = useState(true)

  const load = useCallback(async () => {
    try {
      const data = await api<{ authorities: Authority[] }>('jrb', '/v1/authorities', { session })
      setRows(data.authorities || [])
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
          aria-label="Filter authorities"
          className="input w-64"
          placeholder="filter authorities…"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
        />
        <span className="text-sm text-stone-600">{shown.length} of {rows.length}</span>
      </div>
      <Card>
        {loading ? (
          <div aria-busy="true" aria-label="Loading authorities"><SkeletonRows /></div>
        ) : shown.length === 0 ? (
          <Empty title="No authorities match">Try a different filter.</Empty>
        ) : (
          <table className="w-full">
            <thead>
              <tr className="border-b border-neutral-200">
                <th scope="col" className="th">ID</th>
                <th scope="col" className="th">Authority</th>
                <th scope="col" className="th">Kind</th>
                <th scope="col" className="th">Status</th>
                <th scope="col" className="th">Cert fingerprint</th>
              </tr>
            </thead>
            <tbody>
              {shown.map((a) => (
                <tr key={a.id} className="border-b border-neutral-100 hover:bg-neutral-50">
                  <td className="td font-mono text-xs">{a.id}</td>
                  <td className="td">{a.name}</td>
                  <td className="td text-xs">{a.kind}</td>
                  <td className="td">
                    <Badge tone={a.status === 'active' ? 'green' : a.status === 'suspended' ? 'red' : 'amber'}>
                      {a.status}
                    </Badge>
                  </td>
                  <td className="td font-mono text-xs text-stone-600">
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
