'use client'
import { useLanguage } from '@/i18n/LanguageContext'

export default function PaymentFailure() {
  const { lang } = useLanguage()
  return (
    <main className="min-h-screen bg-black flex items-center justify-center p-6">
      <div className="max-w-md text-center space-y-4">
        <div className="text-5xl">❌</div>
        <h1 className="text-2xl font-bold text-white">
          {lang === 'es' ? 'Pago Fallido' : 'Payment Failed'}
        </h1>
        <p className="text-gray-400">
          {lang === 'es' ? 'Algo salió mal con tu pago. Por favor intentá de nuevo.' : 'Something went wrong with your payment. Please try again.'}
        </p>
        <a href="/" className="inline-block mt-4 px-6 py-3 bg-cyber-green/20 border border-cyber-green/30 text-cyber-green rounded-xl hover:bg-cyber-green/30 transition-all">
          ← {lang === 'es' ? 'Intentar de Nuevo' : 'Try Again'}
        </a>
      </div>
    </main>
  )
}
