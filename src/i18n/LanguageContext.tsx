'use client'
import { createContext, useContext, useState, useEffect, ReactNode } from 'react'
import { Language } from './translations'

interface LanguageContextType {
  lang: Language
  setLang: (lang: Language) => void
  toggle: () => void
}

const LanguageContext = createContext<LanguageContextType>({
  lang: 'en',
  setLang: () => {},
  toggle: () => {},
})

export function LanguageProvider({ children }: { children: ReactNode }) {
  const [lang, setLangState] = useState<Language>('en')
  const [mounted, setMounted] = useState(false)

  useEffect(() => {
    // Check localStorage first
    const stored = localStorage.getItem('wsc-lang') as Language
    if (stored && (stored === 'en' || stored === 'es')) {
      setLangState(stored)
    } else {
      // Auto-detect browser language
      const browserLang = navigator.language.toLowerCase()
      if (browserLang.startsWith('es')) {
        setLangState('es')
      }
    }
    setMounted(true)
  }, [])

  const setLang = (newLang: Language) => {
    setLangState(newLang)
    localStorage.setItem('wsc-lang', newLang)
  }

  const toggle = () => {
    setLang(lang === 'en' ? 'es' : 'en')
  }

  // Avoid hydration mismatch
  if (!mounted) {
    return <>{children}</>
  }

  return (
    <LanguageContext.Provider value={{ lang, setLang, toggle }}>
      {children}
    </LanguageContext.Provider>
  )
}

export function useLanguage() {
  return useContext(LanguageContext)
}
