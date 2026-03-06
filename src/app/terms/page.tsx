'use client'
import { useLanguage } from '@/i18n/LanguageContext'

export default function Terms() {
  const { lang } = useLanguage()
  const es = lang === 'es'

  return (
    <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-20 sm:py-28">
      <h1 className="text-4xl font-black text-white mb-8">{es ? 'Términos de Servicio' : 'Terms of Service'}</h1>
      <div className="prose prose-invert prose-sm max-w-none space-y-6 text-gray-300 leading-relaxed">
        <p className="text-gray-400 text-sm">{es ? 'Última actualización: Febrero 2026' : 'Last updated: February 2026'}</p>

        <h2 className="text-xl font-bold text-white mt-8">{es ? '1. Aceptación de Términos' : '1. Acceptance of Terms'}</h2>
        <p>{es ? 'Al usar WebSecCheck, aceptás estos términos. Nuestro servicio proporciona escaneo y evaluación automatizada de seguridad web. Debés tener al menos 18 años o contar con consentimiento parental para usar este servicio.' : 'By using WebSecCheck, you agree to these terms. Our service provides automated web security scanning and assessment. You must be at least 18 years old or have parental consent to use this service.'}</p>

        <h2 className="text-xl font-bold text-white mt-8">{es ? '2. Uso Autorizado' : '2. Authorized Use'}</h2>
        <p>{es ? 'Solo podés escanear sitios web que seas propietario o tengas autorización escrita explícita para testear. El escaneo no autorizado de sitios de terceros está prohibido y puede violar leyes aplicables. Sos el único responsable de asegurar que tenés la autorización adecuada.' : 'You may only scan websites that you own or have explicit written authorization to test. Unauthorized scanning of third-party websites is prohibited and may violate applicable laws. You are solely responsible for ensuring you have proper authorization.'}</p>

        <h2 className="text-xl font-bold text-white mt-8">{es ? '3. Servicio de Escaneo Gratuito' : '3. Free Scan Service'}</h2>
        <p>{es ? 'Nuestro escaneo gratuito realiza chequeos de seguridad pasivos y no intrusivos contra endpoints de acceso público. Los escaneos gratuitos son limitados y pueden tener restricciones de frecuencia. Los resultados se proporcionan tal cual, con fines informativos.' : 'Our free scan performs passive, non-intrusive security checks against publicly accessible endpoints. Free scans are limited and may be rate-limited. Results are provided as-is for informational purposes.'}</p>

        <h2 className="text-xl font-bold text-white mt-8">{es ? '4. Servicios Pagos' : '4. Paid Services'}</h2>
        <p>{es ? 'Los Reportes de Seguridad y Tests de Penetración se rigen por acuerdos de servicio separados proporcionados al momento de la compra. Los reportes pagos incluyen una garantía de devolución de 30 días. Los tests de penetración requieren un formulario de autorización firmado antes de comenzar.' : 'Security Reports and Penetration Tests are governed by separate service agreements provided at the time of purchase. Paid reports include a 30-day money-back guarantee. Penetration tests require a signed authorization form before commencement.'}</p>

        <h2 className="text-xl font-bold text-white mt-8">{es ? '5. Descargo de Responsabilidad' : '5. Disclaimer'}</h2>
        <p>{es ? 'Nuestros escaneos proporcionan una evaluación puntual y no garantizan seguridad completa. No somos responsables por daños resultantes de vulnerabilidades no detectadas por nuestras herramientas. La seguridad es un proceso continuo — recomendamos evaluaciones regulares.' : 'Our scans provide a point-in-time assessment and do not guarantee complete security. We are not liable for any damages resulting from vulnerabilities not detected by our tools. Security is an ongoing process — we recommend regular assessments.'}</p>

        <h2 className="text-xl font-bold text-white mt-8">{es ? '6. Limitación de Responsabilidad' : '6. Limitation of Liability'}</h2>
        <p>{es ? 'La responsabilidad total de WebSecCheck no excederá el monto pagado por el servicio específico en cuestión. No somos responsables por daños indirectos, incidentales o consecuentes.' : 'WebSecCheck\'s total liability shall not exceed the amount paid for the specific service in question. We are not liable for indirect, incidental, or consequential damages.'}</p>

        <h2 className="text-xl font-bold text-white mt-8">{es ? '7. Divulgación Responsable' : '7. Responsible Disclosure'}</h2>
        <p>{es ? 'Si nuestros escaneos descubren vulnerabilidades críticas, reportaremos los hallazgos solo a vos (el usuario autorizado). Seguimos principios de divulgación responsable y nunca divulgaremos públicamente tus vulnerabilidades.' : 'If our scans discover critical vulnerabilities, we will report findings only to you (the authorized user). We follow responsible disclosure principles and will never publicly disclose your vulnerabilities.'}</p>

        <h2 className="text-xl font-bold text-white mt-8">{es ? '8. Modificaciones' : '8. Modifications'}</h2>
        <p>{es ? 'Nos reservamos el derecho de modificar estos términos en cualquier momento. El uso continuo del servicio constituye aceptación de los términos modificados. Notificaremos a los usuarios registrados de cambios materiales por email.' : 'We reserve the right to modify these terms at any time. Continued use of the service constitutes acceptance of modified terms. We will notify registered users of material changes via email.'}</p>

        <h2 className="text-xl font-bold text-white mt-8">{es ? '9. Contacto' : '9. Contact'}</h2>
        <p>{es ? 'Para preguntas sobre estos términos: legal@webseccheck.com' : 'For questions about these terms: legal@webseccheck.com'}</p>
      </div>
    </div>
  )
}
