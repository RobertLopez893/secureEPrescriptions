// src/utils/sessionGuard.ts
// Guardias de sesión del lado cliente. Todas las páginas internas de un
// rol (después del login QR) deben llamar a requireSession() antes de
// montar su UI. No es una garantía de seguridad (el backend es la fuente
// de verdad) — es UX + evita requests 401 innecesarios.

import { getSession, clearSession, type SessionData } from './api'

export type AppRole = 'Medico' | 'Paciente' | 'Farmaceutico' | 'Administrador'

/**
 * Si el usuario no está autenticado o su rol no está permitido, limpia la
 * sesión local y redirige a la pantalla de acceso correspondiente.
 * Admin siempre pasa — es conveniente para pruebas.
 */
export function requireSession(allowed: AppRole | AppRole[], loginUrl: string): SessionData | null {
  if (typeof window === 'undefined') return null
  const roles = Array.isArray(allowed) ? allowed : [allowed]
  const session = getSession()
  if (!session) {
    window.location.replace(loginUrl)
    return null
  }
  if (session.role !== 'Administrador' && !roles.includes(session.role as AppRole)) {
    clearSession()
    window.location.replace(loginUrl)
    return null
  }
  return session
}

/**
 * Logout centralizado: borra token + sesión de sessionStorage y redirige.
 * Por defecto manda a la landing pública.
 */
export function logout(redirectUrl: string = '/'): void {
  clearSession()
  if (typeof window !== 'undefined') window.location.replace(redirectUrl)
}

/**
 * Ruta de login recomendada por rol. Útil para el helper de 401 que no
 * sabe en qué sección del sitio está el usuario y necesita redirigir a
 * la puerta de entrada correcta.
 */
export function loginUrlFor(role: AppRole | string | undefined): string {
  switch (role) {
    case 'Medico':       return '/doctor'
    case 'Paciente':     return '/patient'
    case 'Farmaceutico': return '/pharmacy/login'
    default:             return '/'
  }
}
