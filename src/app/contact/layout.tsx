import type { Metadata } from 'next'

export const metadata: Metadata = {
  title: 'Contact',
  description: 'Get in touch with WebSecCheck. Questions about website security scanning? We are here to help.',
}

export default function ContactLayout({ children }: { children: React.ReactNode }) {
  return <>{children}</>
}
