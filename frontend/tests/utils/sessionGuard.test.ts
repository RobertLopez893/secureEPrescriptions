import { describe, it, expect, beforeEach, vi } from 'vitest'
import { requireSession, loginUrlFor, logout } from '../../src/utils/sessionGuard'
import { saveSession, clearSession } from '../../src/utils/api'

// Mock muy ligero de sessionStorage + window.location.replace.
// Vitest corre en Node, así que ni uno ni otro existen por defecto.
function setupDom() {
  const store: Record<string, string> = {}
  const storage = {
    getItem: (k: string) => (k in store ? store[k] : null),
    setItem: (k: string, v: string) => { store[k] = String(v) },
    removeItem: (k: string) => { delete store[k] },
    clear: () => { for (const k of Object.keys(store)) delete store[k] },
  }
  const replace = vi.fn()
  ;(globalThis as any).sessionStorage = storage
  ;(globalThis as any).window = { location: { replace } }
  return { storage, replace, store }
}

describe('requireSession', () => {
  beforeEach(() => { setupDom() })

  it('redirige al login cuando no hay sesión', () => {
    const { replace } = setupDom()
    const out = requireSession('Medico', '/doctor')
    expect(out).toBeNull()
    expect(replace).toHaveBeenCalledWith('/doctor')
  })

  it('permite el acceso si el rol coincide', () => {
    const { replace } = setupDom()
    saveSession('t', { id: 1, correo: 'med@x', role: 'Medico' })
    const out = requireSession('Medico', '/doctor')
    expect(out?.role).toBe('Medico')
    expect(replace).not.toHaveBeenCalled()
  })

  it('Administrador pasa aunque el rol pedido sea otro', () => {
    const { replace } = setupDom()
    saveSession('t', { id: 1, correo: 'admin@x', role: 'Administrador' })
    const out = requireSession('Medico', '/doctor')
    expect(out?.role).toBe('Administrador')
    expect(replace).not.toHaveBeenCalled()
  })

  it('redirige y limpia la sesión si el rol no está permitido', () => {
    const { replace, storage } = setupDom()
    saveSession('t', { id: 1, correo: 'pac@x', role: 'Paciente' })
    const out = requireSession('Medico', '/doctor')
    expect(out).toBeNull()
    expect(replace).toHaveBeenCalledWith('/doctor')
    // La sesión debe quedar borrada después del desalojo.
    expect(storage.getItem('rxpro_session')).toBeNull()
    expect(storage.getItem('rxpro_token')).toBeNull()
  })

  it('acepta lista de roles permitidos', () => {
    setupDom()
    saveSession('t', { id: 1, correo: 'f@x', role: 'Farmaceutico' })
    const out = requireSession(['Medico', 'Farmaceutico'], '/pharmacy/login')
    expect(out?.role).toBe('Farmaceutico')
  })
})

describe('logout', () => {
  it('limpia la sesión y redirige a la URL indicada', () => {
    const { replace, storage } = setupDom()
    saveSession('t', { id: 1, correo: 'x', role: 'Medico' })
    logout('/')
    expect(storage.getItem('rxpro_session')).toBeNull()
    expect(replace).toHaveBeenCalledWith('/')
  })
})

describe('loginUrlFor', () => {
  it('mapea cada rol a su pantalla de acceso', () => {
    expect(loginUrlFor('Medico')).toBe('/doctor')
    expect(loginUrlFor('Paciente')).toBe('/patient')
    expect(loginUrlFor('Farmaceutico')).toBe('/pharmacy/login')
  })

  it('cae al root cuando no reconoce el rol', () => {
    expect(loginUrlFor('Administrador')).toBe('/')
    expect(loginUrlFor(undefined)).toBe('/')
    expect(loginUrlFor('Desconocido')).toBe('/')
  })

  it('también funciona después de clearSession', () => {
    setupDom()
    saveSession('t', { id: 1, correo: 'x', role: 'Medico' })
    clearSession()
    // loginUrlFor es puro sobre el string que le pases
    expect(loginUrlFor('Medico')).toBe('/doctor')
  })
})
