'use client'
import { useLanguage } from '@/i18n/LanguageContext'

export default function About() {
  const { lang } = useLanguage()

  const team = [
    { name: 'Shannon AI', role: lang === 'es' ? 'Motor de Pentest Autónomo' : 'Autonomous Pentest Engine', desc: lang === 'es' ? 'Nuestra IA propietaria que piensa como un atacante. Entrenada en miles de exploits reales y en constante aprendizaje.' : 'Our proprietary AI that thinks like an attacker. Trained on thousands of real-world exploits and continuously learning.' },
    { name: lang === 'es' ? 'Equipo de Investigación' : 'Security Research Team', role: lang === 'es' ? 'Expertos en Seguridad Ofensiva' : 'Offensive Security Experts', desc: lang === 'es' ? 'Profesionales certificados OSCP, CEH y GPEN con más de 50 años combinados de experiencia en seguridad ofensiva.' : 'OSCP, CEH, and GPEN certified professionals with combined 50+ years of experience in offensive security.' },
    { name: lang === 'es' ? 'Equipo de Ingeniería' : 'Engineering Team', role: lang === 'es' ? 'Plataforma e Infraestructura' : 'Platform & Infrastructure', desc: lang === 'es' ? 'Construyendo infraestructura escalable y segura que procesa millones de chequeos de seguridad diarios con 99.9% de uptime.' : 'Building scalable, secure infrastructure that processes millions of security checks daily with 99.9% uptime.' },
  ]

  const values = [
    { icon: '🎯', title: lang === 'es' ? 'Precisión Primero' : 'Accuracy First', desc: lang === 'es' ? 'Minimizamos los falsos positivos con verificación multicapa. Cada hallazgo se valida antes de reportar.' : 'We minimize false positives through multi-layer verification. Every finding is validated before reporting.' },
    { icon: '🔐', title: lang === 'es' ? 'Privacidad por Diseño' : 'Privacy by Design', desc: lang === 'es' ? 'Nunca almacenamos tus datos sensibles. Los escaneos son efímeros y los resultados se encriptan en reposo.' : 'We never store your sensitive data. Scans are ephemeral and results are encrypted at rest.' },
    { icon: '🌍', title: lang === 'es' ? 'Seguridad Accesible' : 'Accessible Security', desc: lang === 'es' ? 'La seguridad de nivel empresarial no debería requerir un presupuesto empresarial. Nuestro tier gratuito es genuinamente útil.' : 'Enterprise-grade security should not require an enterprise budget. Our free tier is genuinely useful.' },
    { icon: '🤖', title: lang === 'es' ? 'Potenciado por IA' : 'AI-Augmented', desc: lang === 'es' ? 'Combinamos expertise humano con capacidades de IA para evaluaciones de seguridad más rápidas, profundas y completas.' : 'Combining human expertise with AI capabilities for faster, deeper, and more comprehensive security assessments.' },
  ]

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-20 sm:py-28">
      <div className="text-center mb-16">
        <h1 className="text-4xl sm:text-5xl font-black text-white mb-4">
          {lang === 'es' ? 'La Seguridad No Es Opcional' : 'Security Is Not Optional'}
        </h1>
        <p className="text-gray-400 max-w-2xl mx-auto text-lg">
          {lang === 'es'
            ? 'Somos un equipo de investigadores en ciberseguridad e ingenieros de IA con la misión de hacer la web más segura. Creemos que cada sitio web merece una evaluación de seguridad de nivel empresarial.'
            : 'We\'re a team of cybersecurity researchers and AI engineers on a mission to make the web safer. We believe every website deserves enterprise-grade security assessment.'}
        </p>
      </div>

      <section className="mb-20">
        <h2 className="text-2xl font-bold text-white mb-8 text-center">
          {lang === 'es' ? 'Nuestros Valores' : 'Our Values'}
        </h2>
        <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-6">
          {values.map(v => (
            <div key={v.title} className="card-dark rounded-2xl p-6 text-center">
              <div className="text-3xl mb-3">{v.icon}</div>
              <h3 className="text-white font-bold mb-2">{v.title}</h3>
              <p className="text-gray-400 text-sm">{v.desc}</p>
            </div>
          ))}
        </div>
      </section>

      <section className="mb-20">
        <h2 className="text-2xl font-bold text-white mb-8 text-center">
          {lang === 'es' ? 'El Equipo' : 'The Team'}
        </h2>
        <div className="grid md:grid-cols-3 gap-8">
          {team.map(member => (
            <div key={member.name} className="card-dark rounded-2xl p-8 text-center">
              <div className="w-16 h-16 rounded-full bg-cyber-green/10 border border-cyber-green/20 flex items-center justify-center text-cyber-green text-2xl font-bold mx-auto mb-4">
                {member.name[0]}
              </div>
              <h3 className="text-white font-bold text-lg mb-1">{member.name}</h3>
              <p className="text-cyber-green text-sm mb-3">{member.role}</p>
              <p className="text-gray-400 text-sm">{member.desc}</p>
            </div>
          ))}
        </div>
      </section>

      <section className="card-dark rounded-2xl p-10 text-center">
        <h2 className="text-2xl font-bold text-white mb-4">
          {lang === 'es' ? 'Nuestra Metodología' : 'Our Methodology'}
        </h2>
        <p className="text-gray-400 max-w-3xl mx-auto leading-relaxed">
          {lang === 'es'
            ? 'Nuestro motor de escaneo sigue la metodología OWASP Testing Guide v4, enriquecida con chequeos propietarios desarrollados a partir de la investigación en seguridad ofensiva de nuestro equipo. Combinamos reconocimiento pasivo, escaneo activo y análisis impulsado por IA para entregar insights de seguridad accionables con mínimos falsos positivos. Cada vulnerabilidad se puntúa usando CVSS v3.1 y se mapea a identificadores CWE para cumplimiento y seguimiento.'
            : 'Our scanning engine follows the OWASP Testing Guide v4 methodology, enriched with proprietary checks developed from our team\'s offensive security research. We combine passive reconnaissance, active scanning, and AI-powered analysis to deliver actionable security insights with minimal false positives. Every vulnerability is scored using CVSS v3.1 and mapped to CWE identifiers for compliance and tracking.'}
        </p>
      </section>
    </div>
  )
}
