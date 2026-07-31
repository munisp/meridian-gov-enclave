import { ReactNode, useId } from 'react'
import { AlertCircle } from 'lucide-react'

interface FieldProps {
  label: string
  children: ReactNode | ((id: string, describedBy?: string, invalid?: boolean) => ReactNode)
  error?: string | null
  hint?: string
  required?: boolean
  /** Override the auto-generated control id (children receive it via render prop). */
  id?: string
}

/**
 * Meridian One §5 — mandatory form-field pattern. Auto-wires
 * id / htmlFor / aria-describedby / aria-invalid so labels are always
 * programmatically associated (audit A2) and errors announce via role="alert"
 * (audit A6).
 *
 * Pass the control as a render child: <Field label="TIN">{id => <input id={id} …/>}</Field>
 */
export default function Field({ label, children, error, hint, required, id }: FieldProps) {
  const autoId = useId()
  const controlId = id ?? autoId
  const hintId = `${controlId}-hint`
  const errorId = `${controlId}-error`
  const describedBy = [error ? errorId : null, hint ? hintId : null].filter(Boolean).join(' ') || undefined
  return (
    <div>
      <label className="label" htmlFor={controlId}>
        {label}
        {required && (
          <span aria-hidden="true" className="text-danger-strong">
            {' '}
            *
          </span>
        )}
      </label>
      {typeof children === 'function'
        ? (children as (id: string, describedBy?: string, invalid?: boolean) => ReactNode)(controlId, describedBy, !!error)
        : children}
      {hint && (
        <p id={hintId} className="mt-1 text-xs text-stone-600">
          {hint}
        </p>
      )}
      {error && (
        <p id={errorId} role="alert" className="mt-1 flex items-center gap-1 text-xs text-danger-strong">
          <AlertCircle aria-hidden="true" className="h-3.5 w-3.5 shrink-0" />
          {error}
        </p>
      )}
    </div>
  )
}
