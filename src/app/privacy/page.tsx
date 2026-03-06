'use client'
import { useLanguage } from '@/i18n/LanguageContext'

export default function Privacy() {
  const { lang } = useLanguage()
  const es = lang === 'es'

  return (
    <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-20 sm:py-28">
      <h1 className="text-4xl font-black text-white mb-8">{es ? 'Política de Privacidad' : 'Privacy Policy'}</h1>
      <div className="prose prose-invert prose-sm max-w-none space-y-6 text-gray-300 leading-relaxed">
        <p className="text-gray-400 text-sm">{es ? 'Última actualización: Febrero 2026' : 'Last updated: February 2026'}</p>

        <h2 className="text-xl font-bold text-white mt-8">{es ? '1. Información que Recopilamos' : '1. Information We Collect'}</h2>
        <p>{es ? 'Cuando usás nuestro servicio de escaneo, recopilamos la URL que enviás para análisis. Realizamos chequeos de seguridad solo contra endpoints de acceso público. No accedemos a áreas privadas de tu sitio web, bases de datos o sistemas internos durante los escaneos gratuitos.' : 'When you use our scanning service, we collect the URL you submit for analysis. We perform security checks against publicly accessible endpoints only. We do not access private areas of your website, databases, or internal systems during free scans.'}</p>

        <h2 className="text-xl font-bold text-white mt-8">{es ? '2. Cómo Usamos Tu Información' : '2. How We Use Your Information'}</h2>
        <p>{es ? 'Las URLs enviadas se usan únicamente para realizar la evaluación de seguridad solicitada. Los resultados del escaneo se generan en tiempo real y se te proporcionan directamente. Podemos retener estadísticas de escaneo anonimizadas y agregadas para mejorar nuestro motor.' : 'URLs submitted are used solely to perform the requested security assessment. Scan results are generated in real-time and provided directly to you. We may retain anonymized, aggregate scan statistics to improve our scanning engine.'}</p>

        <h2 className="text-xl font-bold text-white mt-8">{es ? '3. Retención de Datos' : '3. Data Retention'}</h2>
        <p>{es ? 'Los resultados de escaneos gratuitos se retienen por 30 días y luego se eliminan automáticamente. Los datos de reportes pagos se retienen por 12 meses o hasta que solicites su eliminación. No vendemos, alquilamos ni compartimos tus datos de escaneo con terceros.' : 'Free scan results are retained for 30 days and then automatically deleted. Paid report data is retained for 12 months or until you request deletion. We do not sell, rent, or share your scan data with third parties.'}</p>

        <h2 className="text-xl font-bold text-white mt-8">{es ? '4. Seguridad' : '4. Security'}</h2>
        <p>{es ? 'Todos los datos en tránsito están encriptados usando TLS 1.3. Los datos en reposo se encriptan usando AES-256. Nuestra infraestructura está alojada en data centers con cumplimiento SOC 2. Realizamos evaluaciones de seguridad regulares de nuestra propia plataforma.' : 'All data in transit is encrypted using TLS 1.3. Data at rest is encrypted using AES-256. Our infrastructure is hosted in SOC 2 compliant data centers. We conduct regular security assessments of our own platform.'}</p>

        <h2 className="text-xl font-bold text-white mt-8">5. Cookies</h2>
        <p>{es ? 'Usamos cookies esenciales para gestión de sesiones. No usamos cookies de rastreo de terceros ni píxeles publicitarios. Las analíticas, si se usan, respetan la privacidad y no usan cookies.' : 'We use essential cookies for session management. We do not use third-party tracking cookies or advertising pixels. Analytics, if used, are privacy-respecting and cookieless.'}</p>

        <h2 className="text-xl font-bold text-white mt-8">{es ? '6. Tus Derechos' : '6. Your Rights'}</h2>
        <p>{es ? 'Tenés derecho a acceder, corregir o eliminar tus datos en cualquier momento. Podés solicitar una copia de todos los datos que tenemos sobre vos. Para ejercer estos derechos, contactanos a privacy@webseccheck.com.' : 'You have the right to access, correct, or delete your data at any time. You can request a copy of all data we hold about you. To exercise these rights, contact us at privacy@webseccheck.com.'}</p>

        <h2 className="text-xl font-bold text-white mt-8">{es ? '7. Tests de Penetración' : '7. Penetration Testing'}</h2>
        <p>{es ? 'Para tests de penetración pagos, requerimos autorización escrita explícita antes de realizar cualquier prueba activa. Todos los hallazgos se comparten exclusivamente con el contacto autorizado. Acuerdos de NDA están disponibles y son recomendados.' : 'For paid penetration tests, we require explicit written authorization before conducting any active testing. All findings are shared exclusively with the authorized contact. NDA agreements are available and recommended.'}</p>

        <h2 className="text-xl font-bold text-white mt-8">{es ? '8. Contacto' : '8. Contact'}</h2>
        <p>{es ? 'Para consultas de privacidad: privacy@webseccheck.com' : 'For privacy-related inquiries: privacy@webseccheck.com'}</p>
      </div>
    </div>
  )
}
