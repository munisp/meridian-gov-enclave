import { ReactNode } from 'react'
import { Inbox } from 'lucide-react'

export function PageTitle({ title, sub }: { title: string; sub?: string }) {
  return (
    <div className="mb-5">
      <h1 className="text-xl font-bold text-stone-900">{title}</h1>
      {sub && <p className="mt-0.5 text-sm text-stone-600">{sub}</p>}
    </div>
  )
}

export function Card({ children, className = '' }: { children: ReactNode; className?: string }) {
  return <div className={`card p-4 ${className}`}>{children}</div>
}

/** Page-level errors announce via role="alert" (Meridian One §5/§8). */
export function ErrorBox({ error }: { error: string | null }) {
  if (!error) return null
  return (
    <div role="alert" className="mb-4 rounded-lg border border-danger-strong/40 bg-danger px-4 py-2 text-sm text-danger-on">
      {error}
    </div>
  )
}

/** Meridian One §5 — illustration-free empty state (never a blank card). */
export function Empty({ title, children }: { title?: string; children?: ReactNode }) {
  return (
    <div className="flex flex-col items-center rounded-lg border border-dashed border-neutral-300 px-4 py-8 text-center">
      <span className="mb-3 rounded-full bg-neutral-100 p-3">
        <Inbox aria-hidden="true" className="h-6 w-6 text-neutral-500" />
      </span>
      <p className="text-sm font-semibold text-stone-900">{title ?? 'Nothing here yet'}</p>
      {children && <p className="mt-1 text-sm text-stone-600">{children}</p>}
    </div>
  )
}

/** Skeleton matching final layout; pair with aria-busy on the region. */
export function Skeleton({ className = '' }: { className?: string }) {
  return <div aria-hidden="true" className={`skeleton ${className}`} />
}

export function SkeletonRows({ rows = 4 }: { rows?: number }) {
  return (
    <div className="space-y-2" aria-hidden="true">
      {Array.from({ length: rows }).map((_, i) => (
        <Skeleton key={i} className="h-12 w-full" />
      ))}
    </div>
  )
}

export type ChipStatus =
  | 'captured' | 'queued' | 'pending' | 'verified' | 'synced' | 'paid'
  | 'failed' | 'rejected' | 'demo' | 'success' | 'warning' | 'danger' | 'info'

// Meridian One §5 — status is always a chip (semantic surface + on-surface
// text + icon), never coloured text alone.
const STATUS_STYLES: Record<ChipStatus, { cls: string; icon: string }> = {
  captured: { cls: 'bg-info text-info-on', icon: '●' },
  queued: { cls: 'bg-warning text-warning-on', icon: '◷' },
  pending: { cls: 'bg-warning text-warning-on', icon: '◷' },
  verified: { cls: 'bg-success text-success-on', icon: '✓' },
  synced: { cls: 'bg-success text-success-on', icon: '✓' },
  paid: { cls: 'bg-success text-success-on', icon: '✓' },
  failed: { cls: 'bg-danger text-danger-on', icon: '✕' },
  rejected: { cls: 'bg-danger text-danger-on', icon: '✕' },
  demo: { cls: 'bg-neutral-100 text-neutral-800', icon: '◌' },
  success: { cls: 'bg-success text-success-on', icon: '✓' },
  warning: { cls: 'bg-warning text-warning-on', icon: '⚠' },
  danger: { cls: 'bg-danger text-danger-on', icon: '✕' },
  info: { cls: 'bg-info text-info-on', icon: 'ℹ' },
}

export function Chip({ status, children, className = '' }: { status: ChipStatus; children?: ReactNode; className?: string }) {
  const s = STATUS_STYLES[status]
  return (
    <span className={`chip ${s.cls} ${className}`}>
      <span aria-hidden="true">{s.icon}</span>
      {children ?? status}
    </span>
  )
}

/** Backwards-compatible severity badge → semantic chip tokens. */
export function Badge({ tone, children }: { tone: 'green' | 'amber' | 'red' | 'neutral'; children: ReactNode }) {
  const map = {
    green: 'bg-success text-success-on',
    amber: 'bg-warning text-warning-on',
    red: 'bg-danger text-danger-on',
    neutral: 'bg-neutral-100 text-neutral-800',
  }
  return <span className={`chip ${map[tone]}`}>{children}</span>
}

export function bandTone(band: string): 'green' | 'amber' | 'red' | 'neutral' {
  if (band === 'high') return 'red'
  if (band === 'medium') return 'amber'
  if (band === 'low') return 'green'
  return 'neutral'
}
