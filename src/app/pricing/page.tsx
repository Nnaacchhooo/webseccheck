'use client'
import Link from 'next/link'
import { useLanguage } from '@/i18n/LanguageContext'

export default function Pricing() {
  const { lang } = useLanguage()

  const tiers = [
    {
      name: lang === 'es' ? 'Escaneo Gratuito' : 'Free Scan',
      price: '$0',
      period: lang === 'es' ? 'siempre' : 'forever',
      desc: lang === 'es' ? 'Evaluación rápida de seguridad para cualquier sitio web.' : 'Quick security assessment for any website.',
      features: lang === 'es' ? [
        'Chequeos pasivos OWASP Top 10',
        'Puntaje de seguridad general (A-F)',
        'Validación básica SSL/TLS',
        'Chequeo de headers de seguridad HTTP',
        'Resultados instantáneos — sin registro',
        'Link de reporte compartible',
      ] : [
        'OWASP Top 10 passive checks',
        'Overall security score (A-F)',
        'SSL/TLS basic validation',
        'HTTP security headers check',
        'Instant results — no signup',
        'Shareable report link',
      ],
      cta: lang === 'es' ? 'Escanear — Gratis' : 'Scan Now — Free',
      href: '/',
      highlight: false,
    },
    {
      name: lang === 'es' ? 'Reporte de Seguridad' : 'Security Report',
      price: '$49',
      period: lang === 'es' ? 'por escaneo' : 'per scan',
      desc: lang === 'es' ? 'Evaluación completa de vulnerabilidades con guía de remediación.' : 'Comprehensive vulnerability assessment with remediation guidance.',
      features: lang === 'es' ? [
        'Los 45+ chequeos de seguridad',
        'Puntuación de riesgo CVSS v3.1',
        'Vulnerabilidades priorizadas por riesgo',
        'Hoja de ruta de remediación detallada',
        'Comparación con benchmarks de la industria',
        'Exportación PDF y acceso API',
        'Alertas por email ante cambios',
        'Garantía de devolución de 30 días',
      ] : [
        'All 45+ security checks',
        'CVSS v3.1 risk scoring',
        'Priority-ranked vulnerabilities',
        'Detailed remediation roadmap',
        'Industry benchmark comparison',
        'PDF export & API access',
        'Email alerts for changes',
        '30-day money-back guarantee',
      ],
      cta: lang === 'es' ? 'Obtener Reporte' : 'Get Security Report',
      href: '/contact',
      highlight: true,
      badge: lang === 'es' ? 'Más Popular' : 'Most Popular',
    },
    {
      name: lang === 'es' ? 'Consultoría de Seguridad' : 'Security Consulting',
      price: lang === 'es' ? 'A medida' : 'Custom',
      period: lang === 'es' ? 'por proyecto' : 'per project',
      desc: lang === 'es' ? 'Consultoría de ciberseguridad experta adaptada a tu negocio.' : 'Expert cybersecurity consulting tailored to your business needs.',
      features: lang === 'es' ? [
        'Pentesting completo (manual + IA)',
        'Evaluación de vulnerabilidades y remediación',
        'Revisión de arquitectura de seguridad',
        'Guía de cumplimiento (ISO 27001, SOC 2)',
        'Realizado por expertos certificados (OSCP/CEH)',
        'NDA y documentación de cumplimiento',
        'Resumen ejecutivo para stakeholders',
        'Canal de soporte dedicado',
      ] : [
        'Full penetration testing (manual + AI)',
        'Vulnerability assessment & remediation',
        'Security architecture review',
        'Compliance guidance (ISO 27001, SOC 2)',
        'Conducted by certified experts (OSCP/CEH)',
        'NDA & compliance documentation',
        'Executive summary for stakeholders',
        'Dedicated support channel',
      ],
      cta: lang === 'es' ? 'Contactanos' : 'Contact Us',
      href: '/contact',
      highlight: false,
    },
  ]

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-20 sm:py-28">
      <div className="text-center mb-16">
        <h1 className="text-4xl sm:text-5xl font-black text-white mb-4">
          {lang === 'es' ? 'Precios Simples y Transparentes' : 'Simple, Transparent Pricing'}
        </h1>
        <p className="text-gray-400 max-w-xl mx-auto text-lg">
          {lang === 'es' ? 'Desde escaneos gratuitos hasta pentests completos. Elegí el nivel de seguridad que necesitás.' : 'From free scans to full penetration tests. Choose the depth of security you need.'}
        </p>
      </div>

      <div className="grid lg:grid-cols-3 gap-8 items-start">
        {tiers.map(tier => (
          <div key={tier.name} className={`rounded-2xl p-8 relative transition-all hover:scale-[1.02] ${tier.highlight ? 'bg-gradient-to-b from-cyber-green/10 to-cyber-gray border-2 border-cyber-green/30 glow-green' : 'card-dark'}`}>
            {tier.badge && (
              <div className="absolute -top-3 left-1/2 -translate-x-1/2 gradient-cta text-black text-xs font-bold px-4 py-1 rounded-full">
                {tier.badge}
              </div>
            )}
            <div className="mb-6">
              <h3 className="text-xl font-bold text-white mb-1">{tier.name}</h3>
              <p className="text-gray-400 text-sm">{tier.desc}</p>
            </div>
            <div className="mb-6">
              <span className="text-5xl font-black text-white">{tier.price}</span>
              <span className="text-gray-500 text-sm ml-2">/ {tier.period}</span>
            </div>
            <ul className="space-y-3 mb-8">
              {tier.features.map(f => (
                <li key={f} className="flex items-start gap-3 text-sm text-gray-300">
                  <svg className="w-5 h-5 text-cyber-green flex-shrink-0 mt-0.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                  </svg>
                  {f}
                </li>
              ))}
            </ul>
            <Link
              href={tier.href}
              className={`block text-center py-3 rounded-xl font-semibold text-sm transition ${tier.highlight ? 'gradient-cta text-black hover:opacity-90' : 'border border-white/10 text-white hover:border-cyber-green/30'}`}
            >
              {tier.cta}
            </Link>
          </div>
        ))}
      </div>

      <div className="mt-16 text-center">
        <p className="text-gray-500 text-sm">
          {lang === 'es'
            ? <>Todos los planes incluyen infraestructura SOC 2. Planes enterprise disponibles — <Link href="/contact" className="text-cyber-green hover:underline">contactanos</Link>.</>
            : <>All plans include SOC 2 compliant infrastructure. Enterprise plans available — <Link href="/contact" className="text-cyber-green hover:underline">contact us</Link>.</>
          }
        </p>
      </div>
    </div>
  )
}
