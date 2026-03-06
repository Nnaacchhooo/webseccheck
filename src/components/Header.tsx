'use client'
import Link from 'next/link'
import { useState } from 'react'
import { useLanguage } from '@/i18n/LanguageContext'
import { t } from '@/i18n/translations'

export default function Header() {
  const [mobileOpen, setMobileOpen] = useState(false)
  const { lang, toggle } = useLanguage()

  const links = [
    { href: '/', label: t('header.scanner', lang) },
    { href: '/pricing', label: t('header.pricing', lang) },
    { href: '/about', label: t('header.about', lang) },
    { href: '/contact', label: t('header.contact', lang) },
  ]

  return (
    <header className="fixed top-0 w-full z-50 bg-cyber-darkblue/80 backdrop-blur-xl border-b border-white/5">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          <Link href="/" className="flex items-center gap-2">
            <span className="text-2xl font-black text-cyber-green glow-green-sm px-2 py-0.5 border border-cyber-green/30 rounded">WS</span>
            <span className="text-white font-semibold text-lg hidden sm:block">WebSecCheck</span>
          </Link>

          <nav className="hidden md:flex items-center gap-8">
            {links.map(l => (
              <Link key={l.href} href={l.href} className="text-gray-300 hover:text-cyber-green transition-colors text-sm font-medium">
                {l.label}
              </Link>
            ))}

            {/* Language Toggle */}
            <button
              onClick={toggle}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-white/10 hover:border-cyber-green/30 transition-all text-sm font-medium text-gray-300 hover:text-white"
              title={lang === 'en' ? 'Cambiar a Español' : 'Switch to English'}
            >
              {lang === 'en' ? '🇺🇸 EN' : '🇦🇷 ES'}
            </button>

            <Link href="/" className="gradient-cta text-black font-semibold text-sm px-5 py-2 rounded-lg hover:opacity-90 transition">
              {t('header.scanNow', lang)}
            </Link>
          </nav>

          <div className="flex items-center gap-3 md:hidden">
            {/* Mobile Language Toggle */}
            <button
              onClick={toggle}
              className="flex items-center gap-1 px-2 py-1 rounded-lg border border-white/10 text-xs font-medium text-gray-300"
            >
              {lang === 'en' ? '🇺🇸' : '🇦🇷'}
            </button>

            <button onClick={() => setMobileOpen(!mobileOpen)} className="text-gray-300 hover:text-white">
              <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                {mobileOpen ? (
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                ) : (
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 12h16M4 18h16" />
                )}
              </svg>
            </button>
          </div>
        </div>

        {mobileOpen && (
          <div className="md:hidden pb-4 space-y-2">
            {links.map(l => (
              <Link key={l.href} href={l.href} onClick={() => setMobileOpen(false)} className="block px-3 py-2 text-gray-300 hover:text-cyber-green transition-colors text-sm">
                {l.label}
              </Link>
            ))}
            <Link href="/" onClick={() => setMobileOpen(false)} className="block gradient-cta text-black font-semibold text-sm px-5 py-2 rounded-lg text-center mt-2">
              {t('header.scanNow', lang)}
            </Link>
          </div>
        )}
      </div>
    </header>
  )
}
