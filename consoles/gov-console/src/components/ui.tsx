import { ReactNode } from 'react'

export function PageTitle({ title, sub }: { title: string; sub?: string }) {
  return (
    <div className="mb-5">
      <h1 className="text-xl font-bold text-sand-900">{title}</h1>
      {sub && <p className="mt-0.5 text-sm text-sand-500">{sub}</p>}
    </div>
  )
}

export function Card({ children, className = '' }: { children: ReactNode; className?: string }) {
  return <div className={`card p-4 ${className}`}>{children}</div>
}

export function ErrorBox({ error }: { error: string | null }) {
  if (!error) return null
  return (
    <div className="mb-4 rounded-lg border border-clay-500/40 bg-clay-100 px-4 py-2 text-sm text-clay-700">
      {error}
    </div>
  )
}

export function Empty({ children }: { children: ReactNode }) {
  return <div className="rounded-lg border border-dashed border-sand-300 p-8 text-center text-sm text-sand-400">{children}</div>
}

export function Badge({ tone, children }: { tone: 'green' | 'amber' | 'red' | 'neutral'; children: ReactNode }) {
  const map = {
    green: 'bg-moss-100 text-moss-700',
    amber: 'bg-sand-200 text-sand-700',
    red: 'bg-clay-100 text-clay-700',
    neutral: 'bg-sand-100 text-sand-600',
  }
  return <span className={`badge ${map[tone]}`}>{children}</span>
}

export function bandTone(band: string): 'green' | 'amber' | 'red' | 'neutral' {
  if (band === 'high') return 'red'
  if (band === 'medium') return 'amber'
  if (band === 'low') return 'green'
  return 'neutral'
}
