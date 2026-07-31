import { useTranslation } from 'react-i18next'
import { LANGS, setLang, Lang } from '../i18n'

/** Language switcher (spec §10) — persisted per-device; all languages LTR. */
export default function LangSwitcher({ dark = false }: { dark?: boolean }) {
  const { t, i18n } = useTranslation('common')
  return (
    <label className={`inline-flex items-center gap-1 text-xs ${dark ? 'text-brand-100' : 'text-stone-600'}`}>
      <span>{t('lang.label')}</span>
      <select
        className={`rounded-md border px-1.5 py-1 text-xs focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-400 ${
          dark ? 'border-brand-700 bg-brand-900 text-white' : 'border-neutral-300 bg-white text-stone-900'
        }`}
        value={i18n.language}
        onChange={(e) => setLang(e.target.value as Lang)}
        aria-label={t('lang.label')}
      >
        {LANGS.map((l) => (
          <option key={l} value={l}>
            {t(`lang.${l}`)}
          </option>
        ))}
      </select>
    </label>
  )
}
