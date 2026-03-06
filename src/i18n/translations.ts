export type Language = 'en' | 'es'

export const translations = {
  // Header
  header: {
    scanner: { en: 'Scanner', es: 'Escáner' },
    pricing: { en: 'Pricing', es: 'Precios' },
    about: { en: 'About', es: 'Nosotros' },
    contact: { en: 'Contact', es: 'Contacto' },
    scanNow: { en: 'Scan Now — Free', es: 'Escanear — Gratis' },
  },

  // Hero
  hero: {
    badge: { en: 'Security Engine Online — OWASP Top 10 Framework', es: 'Motor de Seguridad Online — Framework OWASP Top 10' },
    title1: { en: 'How Secure Is', es: '¿Qué Tan Seguro Es' },
    title2: { en: 'Your Website?', es: 'Tu Sitio Web?' },
    subtitle: { en: 'Run an instant security assessment against 45+ attack vectors.', es: 'Ejecutá un análisis de seguridad instantáneo contra 45+ vectores de ataque.' },
    subtitleExtra: { en: 'Get actionable results in seconds — no signup, no credit card.', es: 'Obtené resultados accionables en segundos — sin registro, sin tarjeta.' },
  },

  // Trust signals
  trust: {
    owasp: { en: 'OWASP Top 10 Framework', es: 'Framework OWASP Top 10' },
    checks: { en: '45+ Security Checks', es: '45+ Chequeos de Seguridad' },
    results: { en: 'Results in 30 Seconds', es: 'Resultados en 30 Segundos' },
  },

  // How it works
  howItWorks: {
    title: { en: 'How It Works', es: 'Cómo Funciona' },
    subtitle: { en: 'Three simple steps to comprehensive security insights.', es: 'Tres simples pasos para un análisis de seguridad completo.' },
    step1Title: { en: 'Enter Your URL', es: 'Ingresá Tu URL' },
    step1Desc: { en: 'Type your website address. No signup required — start scanning immediately.', es: 'Escribí la dirección de tu sitio web. Sin registro — empezá a escanear de inmediato.' },
    step2Title: { en: 'We Scan', es: 'Escaneamos' },
    step2Desc: { en: 'Our AI-powered engine runs 45+ security checks against OWASP Top 10 and beyond.', es: 'Nuestro motor impulsado por IA ejecuta 45+ chequeos de seguridad contra OWASP Top 10 y más.' },
    step3Title: { en: 'Get Results', es: 'Obtené Resultados' },
    step3Desc: { en: 'Receive a detailed security score with prioritized findings and remediation steps.', es: 'Recibí un puntaje de seguridad detallado con hallazgos priorizados y pasos de remediación.' },
  },

  // What we check
  whatWeCheck: {
    title: { en: 'What We Check', es: 'Qué Analizamos' },
    subtitle: { en: 'Comprehensive coverage across six critical security domains.', es: 'Cobertura completa en seis dominios críticos de seguridad.' },
    sslTitle: { en: 'SSL/TLS Security', es: 'Seguridad SSL/TLS' },
    sslDesc: { en: 'Certificate validity, protocol versions, cipher strength, HSTS implementation, and certificate chain analysis.', es: 'Validez de certificados, versiones de protocolo, fortaleza de cifrado, implementación HSTS y análisis de cadena de certificados.' },
    headersTitle: { en: 'HTTP Headers', es: 'Headers HTTP' },
    headersDesc: { en: 'Content-Security-Policy, X-Frame-Options, CORS configuration, and all critical security headers.', es: 'Content-Security-Policy, X-Frame-Options, configuración CORS y todos los headers de seguridad críticos.' },
    dnsTitle: { en: 'DNS Security', es: 'Seguridad DNS' },
    dnsDesc: { en: 'DNSSEC validation, SPF/DKIM/DMARC records, zone transfer protection, and DNS-based threats.', es: 'Validación DNSSEC, registros SPF/DKIM/DMARC, protección de transferencia de zona y amenazas basadas en DNS.' },
    serverTitle: { en: 'Server Exposure', es: 'Exposición del Servidor' },
    serverDesc: { en: 'Open ports, server version disclosure, directory listing, debug endpoints, and admin panel detection.', es: 'Puertos abiertos, divulgación de versión del servidor, listado de directorios, endpoints de debug y detección de paneles de admin.' },
    cookieTitle: { en: 'Cookie Security', es: 'Seguridad de Cookies' },
    cookieDesc: { en: 'Secure/HttpOnly flags, SameSite policy, session management, and cookie-based attack vectors.', es: 'Flags Secure/HttpOnly, política SameSite, gestión de sesiones y vectores de ataque basados en cookies.' },
    cmsTitle: { en: 'CMS Vulnerabilities', es: 'Vulnerabilidades CMS' },
    cmsDesc: { en: 'WordPress, Drupal, Joomla plugin vulnerabilities, outdated versions, and known CVEs.', es: 'Vulnerabilidades en plugins de WordPress, Drupal, Joomla, versiones desactualizadas y CVEs conocidos.' },
  },

  // Testimonials
  testimonials: {
    title: { en: 'Trusted by Developers & Teams', es: 'La Confianza de Desarrolladores y Equipos' },
    subtitle: { en: 'See what security-conscious professionals say about WebSecCheck.', es: 'Mirá lo que dicen los profesionales de seguridad sobre WebSecCheck.' },
    t1Quote: { en: 'WebSecCheck revealed we were missing critical security headers like CSP and X-Frame-Options across our entire platform. We fixed them within hours and avoided what could have been a serious clickjacking vulnerability.', es: 'WebSecCheck reveló que nos faltaban headers de seguridad críticos como CSP y X-Frame-Options en toda nuestra plataforma. Los arreglamos en horas y evitamos lo que podría haber sido una vulnerabilidad seria de clickjacking.' },
    t2Quote: { en: 'I had no idea our SSL certificate was using an outdated TLS version. The scan flagged it immediately, and the remediation steps were so clear that even my non-technical team could understand the urgency.', es: 'No tenía idea de que nuestro certificado SSL usaba una versión de TLS desactualizada. El escaneo lo detectó de inmediato, y los pasos de remediación fueron tan claros que hasta mi equipo no técnico pudo entender la urgencia.' },
    t3Quote: { en: 'We run every client site through WebSecCheck before launch now. It catches things like open admin panels and missing HSTS headers that manual reviews always miss. It\'s become part of our QA checklist.', es: 'Ahora pasamos cada sitio de cliente por WebSecCheck antes de lanzar. Detecta cosas como paneles de admin abiertos y headers HSTS faltantes que las revisiones manuales siempre pasan por alto. Se convirtió en parte de nuestro checklist de QA.' },
    t4Quote: { en: 'What used to take me 2-3 hours of manual security auditing now takes 30 seconds. The detailed breakdown by category makes it easy to prioritize fixes and explain issues to clients.', es: 'Lo que me llevaba 2-3 horas de auditoría manual de seguridad ahora toma 30 segundos. El desglose detallado por categoría hace fácil priorizar arreglos y explicar problemas a los clientes.' },
  },

  // Stats
  stats: {
    scanned: { en: 'Websites Scanned', es: 'Sitios Escaneados' },
    checks: { en: 'Security Checks', es: 'Chequeos de Seguridad' },
    uptime: { en: 'Uptime SLA', es: 'SLA de Uptime' },
    scanTime: { en: 'Average Scan Time', es: 'Tiempo Promedio de Escaneo' },
  },

  // CTA
  cta: {
    title: { en: 'Ready to Secure Your Website?', es: '¿Listo Para Proteger Tu Sitio Web?' },
    subtitle: { en: 'Start with a free scan. Get enterprise-grade security insights in seconds.', es: 'Empezá con un escaneo gratuito. Obtené información de seguridad de nivel empresarial en segundos.' },
    startScan: { en: 'Start Free Scan', es: 'Escaneo Gratuito' },
    viewPricing: { en: 'View Pricing', es: 'Ver Precios' },
  },

  // Scanner
  scanner: {
    placeholder: { en: 'Enter your website URL (e.g., example.com)', es: 'Ingresá la URL de tu sitio (ej: ejemplo.com)' },
    scanButton: { en: 'Scan Now — Free', es: 'Escanear — Gratis' },
    scanning: { en: 'Scanning...', es: 'Escaneando...' },
    scanningUrl: { en: 'Scanning', es: 'Escaneando' },
    runningChecks: { en: 'Running 45+ security checks against OWASP Top 10', es: 'Ejecutando 45+ chequeos de seguridad contra OWASP Top 10' },
    estimatedScore: { en: 'Estimated Security Score', es: 'Puntaje de Seguridad Estimado' },
    unlockFull: { en: 'Unlock full report for your exact score', es: 'Desbloqueá el reporte completo para tu puntaje exacto' },
    checks: { en: 'checks', es: 'chequeos' },
    passed: { en: 'passed', es: 'aprobados' },
    warnings: { en: 'warnings', es: 'advertencias' },
    failed: { en: 'failed', es: 'fallidos' },
    freePreview: { en: 'Free Preview', es: 'Vista Previa Gratuita' },
    ofChecks: { en: 'of', es: 'de' },
    moreChecks: { en: 'More Critical Checks Performed', es: 'Chequeos Críticos Más Realizados' },
    vulnerabilities: { en: 'vulnerabilities that need immediate attention', es: 'vulnerabilidades que necesitan atención inmediata' },
    vulnerability: { en: 'vulnerability that needs immediate attention', es: 'vulnerabilidad que necesita atención inmediata' },
    additionalVulns: { en: 'additional', es: 'más' },
    urgency: { en: 'Your competitors can see these vulnerabilities. Hackers scan for these daily.', es: 'Tus competidores pueden ver estas vulnerabilidades. Los hackers las buscan a diario.' },
    leftAtPrice: { en: 'left at this price', es: 'a este precio' },
    unlockAll: { en: 'Unlock All', es: 'Desbloqueá Los' },
    securityChecks: { en: 'Security Checks', es: 'Chequeos de Seguridad' },
    morePerformed: { en: 'more critical checks', es: 'chequeos críticos más' },
    werePerformed: { en: 'were performed on your site.', es: 'fueron realizados en tu sitio.' },
    getExact: { en: 'Get your exact score, detailed remediation steps, priority action plan, and code examples.', es: 'Obtené tu puntaje exacto, pasos de remediación detallados, plan de acción prioritario y ejemplos de código.' },
    emailPlaceholder: { en: 'your@email.com', es: 'tu@email.com' },
    getReport: { en: 'Get Full Report — $49', es: 'Reporte Completo — $49' },
    redirecting: { en: 'Redirecting to payment...', es: 'Redirigiendo al pago...' },
    instantDelivery: { en: 'Instant delivery · Detailed remediation steps · Money-back guarantee', es: 'Entrega inmediata · Pasos de remediación detallados · Garantía de devolución' },
    reportSent: { en: 'Report Sent!', es: '¡Reporte Enviado!' },
    reportSentTo: { en: 'Your full security report has been sent to', es: 'Tu reporte completo de seguridad fue enviado a' },
    score: { en: 'Score', es: 'Puntaje' },
    grade: { en: 'Grade', es: 'Grado' },
    checkInbox: { en: 'Check your inbox (and spam folder)', es: 'Revisá tu bandeja de entrada (y la carpeta de spam)' },
    enterEmail: { en: 'Please enter your email address to receive the report.', es: 'Por favor ingresá tu email para recibir el reporte.' },
  },

  // Footer
  footer: {
    description: { en: 'Enterprise-grade web security scanning powered by AI. Protect your digital assets.', es: 'Escaneo de seguridad web de nivel empresarial impulsado por IA. Protegé tus activos digitales.' },
    product: { en: 'Product', es: 'Producto' },
    freeScanner: { en: 'Free Scanner', es: 'Escáner Gratuito' },
    securityReport: { en: 'Security Report', es: 'Reporte de Seguridad' },
    penTest: { en: 'Penetration Test', es: 'Test de Penetración' },
    company: { en: 'Company', es: 'Empresa' },
    aboutUs: { en: 'About Us', es: 'Nosotros' },
    contact: { en: 'Contact', es: 'Contacto' },
    privacy: { en: 'Privacy Policy', es: 'Política de Privacidad' },
    terms: { en: 'Terms of Service', es: 'Términos de Servicio' },
    security: { en: 'Security', es: 'Seguridad' },
    rights: { en: 'All rights reserved.', es: 'Todos los derechos reservados.' },
    tagline: { en: 'Securing the web, one scan at a time.', es: 'Asegurando la web, un escaneo a la vez.' },
  },

  // Pricing
  pricing: {
    title: { en: 'Simple, Transparent Pricing', es: 'Precios Simples y Transparentes' },
    subtitle: { en: 'Choose the plan that fits your security needs.', es: 'Elegí el plan que se ajuste a tus necesidades de seguridad.' },
    free: { en: 'Free', es: 'Gratis' },
    freeDesc: { en: 'Quick security overview', es: 'Resumen rápido de seguridad' },
    freeCta: { en: 'Start Free Scan', es: 'Escaneo Gratuito' },
    report: { en: 'Full Report', es: 'Reporte Completo' },
    reportDesc: { en: 'Detailed security analysis', es: 'Análisis de seguridad detallado' },
    reportCta: { en: 'Get Full Report', es: 'Obtener Reporte' },
    pentest: { en: 'Security Consulting', es: 'Consultoría de Seguridad' },
    pentestDesc: { en: 'Expert-led assessment', es: 'Evaluación liderada por expertos' },
    pentestCta: { en: 'Contact Us', es: 'Contactanos' },
    popular: { en: 'Most Popular', es: 'Más Popular' },
  },

  // About
  about: {
    title: { en: 'About WebSecCheck', es: 'Sobre WebSecCheck' },
    subtitle: { en: 'We believe every website deserves enterprise-grade security.', es: 'Creemos que cada sitio web merece seguridad de nivel empresarial.' },
  },

  // Contact
  contact: {
    title: { en: 'Contact Us', es: 'Contactanos' },
    subtitle: { en: 'Have questions? We\'d love to hear from you.', es: '¿Tenés preguntas? Nos encantaría escucharte.' },
    name: { en: 'Name', es: 'Nombre' },
    email: { en: 'Email', es: 'Email' },
    message: { en: 'Message', es: 'Mensaje' },
    send: { en: 'Send Message', es: 'Enviar Mensaje' },
  },

  // Report pages
  report: {
    successTitle: { en: 'Payment Successful!', es: '¡Pago Exitoso!' },
    successDesc: { en: 'Your security report will be sent to your email shortly.', es: 'Tu reporte de seguridad será enviado a tu email en breve.' },
    failureTitle: { en: 'Payment Failed', es: 'Pago Fallido' },
    failureDesc: { en: 'Something went wrong with your payment. Please try again.', es: 'Algo salió mal con tu pago. Por favor intentá de nuevo.' },
    pendingTitle: { en: 'Payment Pending', es: 'Pago Pendiente' },
    pendingDesc: { en: 'Your payment is being processed. You\'ll receive your report once confirmed.', es: 'Tu pago está siendo procesado. Vas a recibir tu reporte una vez confirmado.' },
    backHome: { en: 'Back to Home', es: 'Volver al Inicio' },
  },

  // Pentest pages
  pentest: {
    title: { en: 'Premium Penetration Test', es: 'Test de Penetración Premium' },
    subtitle: { en: 'Expert-led security assessment for your website.', es: 'Evaluación de seguridad liderada por expertos para tu sitio web.' },
    successTitle: { en: 'Pentest Order Confirmed!', es: '¡Pedido de Pentest Confirmado!' },
    successDesc: { en: 'Our security team will contact you within 24 hours.', es: 'Nuestro equipo de seguridad te contactará dentro de las 24 horas.' },
    failureTitle: { en: 'Payment Failed', es: 'Pago Fallido' },
    failureDesc: { en: 'Something went wrong. Please try again or contact support.', es: 'Algo salió mal. Por favor intentá de nuevo o contactá a soporte.' },
    pendingTitle: { en: 'Payment Pending', es: 'Pago Pendiente' },
    pendingDesc: { en: 'Your payment is being processed.', es: 'Tu pago está siendo procesado.' },
  },

  // Privacy
  privacy: {
    title: { en: 'Privacy Policy', es: 'Política de Privacidad' },
  },

  // Terms
  terms: {
    title: { en: 'Terms of Service', es: 'Términos de Servicio' },
  },
}

export function t(key: string, lang: Language): string {
  const keys = key.split('.')
  let value: any = translations
  for (const k of keys) {
    value = value?.[k]
  }
  return value?.[lang] || value?.['en'] || key
}
