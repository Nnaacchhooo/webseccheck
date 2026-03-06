'use client'
import { useLanguage } from '@/i18n/LanguageContext'

export default function PaymentSuccess() {
  const { lang } = useLanguage()
  return (
    <main className="min-h-screen bg-black flex items-center justify-center p-6">
      <div className="max-w-md text-center space-y-4">
        <div className="text-5xl">✅</div>
        <h1 className="text-2xl font-bold text-white">
          {lang === 'es' ? '¡Pago Exitoso!' : 'Payment Successful!'}
        </h1>
        <p className="text-gray-400">
          {lang === 'es' ? 'Tu reporte de seguridad se está generando y será enviado a tu email en breve.' : 'Your security report is being generated and will be sent to your email shortly.'}
        </p>
        <p className="text-gray-500 text-sm">
          {lang === 'es' ? 'Revisá tu bandeja de entrada (y la carpeta de spam) en los próximos minutos.' : 'Check your inbox (and spam folder) in the next few minutes.'}
        </p>
        <a href="/" className="inline-block mt-4 px-6 py-3 bg-cyber-green/20 border border-cyber-green/30 text-cyber-green rounded-xl hover:bg-cyber-green/30 transition-all">
          ← {lang === 'es' ? 'Volver a WebSecCheck' : 'Back to WebSecCheck'}
        </a>
      </div>
    </main>
  )
}
