'use client'
import { useLanguage } from '@/i18n/LanguageContext'

export default function PaymentPending() {
  const { lang } = useLanguage()
  return (
    <main className="min-h-screen bg-black flex items-center justify-center p-6">
      <div className="max-w-md text-center space-y-4">
        <div className="text-5xl">⏳</div>
        <h1 className="text-2xl font-bold text-white">
          {lang === 'es' ? 'Pago Pendiente' : 'Payment Pending'}
        </h1>
        <p className="text-gray-400">
          {lang === 'es' ? 'Tu pago está siendo procesado. Te enviaremos el reporte una vez confirmado.' : 'Your payment is being processed. We\'ll send your report once the payment is confirmed.'}
        </p>
        <a href="/" className="inline-block mt-4 px-6 py-3 bg-cyber-green/20 border border-cyber-green/30 text-cyber-green rounded-xl hover:bg-cyber-green/30 transition-all">
          ← {lang === 'es' ? 'Volver a WebSecCheck' : 'Back to WebSecCheck'}
        </a>
      </div>
    </main>
  )
}
