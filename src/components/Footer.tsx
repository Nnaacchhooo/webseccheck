'use client'
import Link from 'next/link'
import { useLanguage } from '@/i18n/LanguageContext'
import { t } from '@/i18n/translations'

export default function Footer() {
  const { lang } = useLanguage()

  return (
    <footer className="bg-cyber-darkblue border-t border-white/5">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-8">
          <div>
            <div className="flex items-center gap-2 mb-4">
              <span className="text-xl font-black text-cyber-green px-2 py-0.5 border border-cyber-green/30 rounded">WS</span>
              <span className="text-white font-semibold">WebSecCheck</span>
            </div>
            <p className="text-gray-400 text-sm">{t('footer.description', lang)}</p>
          </div>

          <div>
            <h4 className="text-white font-semibold mb-4 text-sm uppercase tracking-wider">{t('footer.product', lang)}</h4>
            <div className="space-y-2">
              <Link href="/" className="block text-gray-400 hover:text-cyber-green text-sm transition-colors">{t('footer.freeScanner', lang)}</Link>
              <Link href="/pricing" className="block text-gray-400 hover:text-cyber-green text-sm transition-colors">{t('footer.securityReport', lang)}</Link>
              <Link href="/pricing" className="block text-gray-400 hover:text-cyber-green text-sm transition-colors">{t('footer.penTest', lang)}</Link>
            </div>
          </div>

          <div>
            <h4 className="text-white font-semibold mb-4 text-sm uppercase tracking-wider">{t('footer.company', lang)}</h4>
            <div className="space-y-2">
              <Link href="/about" className="block text-gray-400 hover:text-cyber-green text-sm transition-colors">{t('footer.aboutUs', lang)}</Link>
              <Link href="/contact" className="block text-gray-400 hover:text-cyber-green text-sm transition-colors">{t('footer.contact', lang)}</Link>
              <Link href="/privacy" className="block text-gray-400 hover:text-cyber-green text-sm transition-colors">{t('footer.privacy', lang)}</Link>
              <Link href="/terms" className="block text-gray-400 hover:text-cyber-green text-sm transition-colors">{t('footer.terms', lang)}</Link>
            </div>
          </div>

          <div>
            <h4 className="text-white font-semibold mb-4 text-sm uppercase tracking-wider">{t('footer.security', lang)}</h4>
            <div className="space-y-2 text-gray-400 text-sm">
              <p>OWASP Top 10 Framework</p>
              <p>CVSS v3.1 Scoring</p>
              <p>SOC 2 Compliant</p>
              <p>GDPR Ready</p>
            </div>
          </div>
        </div>

        <div className="border-t border-white/5 mt-10 pt-8 flex flex-col sm:flex-row justify-between items-center gap-4">
          <p className="text-gray-500 text-sm">© {new Date().getFullYear()} WebSecCheck. {t('footer.rights', lang)}</p>
          <p className="text-gray-600 text-xs">{t('footer.tagline', lang)}</p>
        </div>
      </div>
    </footer>
  )
}
