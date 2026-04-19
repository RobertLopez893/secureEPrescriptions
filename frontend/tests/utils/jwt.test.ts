import { describe, it, expect } from 'vitest'
import { decodeJwtPayload } from '../../src/utils/api'

// Helper: base64url-encode a JSON payload (sin depender de libs extra).
function b64url(json: unknown): string {
  const s = JSON.stringify(json)
  // btoa trabaja en latin1; el payload aquí es ASCII, basta.
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

function fakeJwt(payload: unknown): string {
  const header  = b64url({ alg: 'HS256', typ: 'JWT' })
  const body    = b64url(payload)
  const sig     = 'sig'  // no se verifica en el cliente
  return `${header}.${body}.${sig}`
}

describe('decodeJwtPayload', () => {
  it('decodifica el payload de un JWT bien formado', () => {
    const token = fakeJwt({ sub: 'demo@rxpro', role: 'Medico', id: 42 })
    const out = decodeJwtPayload(token)
    expect(out).toEqual({ sub: 'demo@rxpro', role: 'Medico', id: 42 })
  })

  it('maneja padding base64url faltante', () => {
    // payload diseñado para necesitar padding al decodificar
    const token = fakeJwt({ sub: 'x', role: 'Paciente', id: 1, extra: 'abc' })
    expect(decodeJwtPayload(token)).not.toBeNull()
  })

  it('retorna null si el token no tiene tres segmentos', () => {
    expect(decodeJwtPayload('no.jwt')).toBeNull()
    expect(decodeJwtPayload('')).toBeNull()
    expect(decodeJwtPayload('a.b.c.d')).toBeNull()
  })

  it('retorna null si el payload no es JSON válido', () => {
    const garbage = 'header.' + btoa('not json').replace(/=+$/, '') + '.sig'
    expect(decodeJwtPayload(garbage)).toBeNull()
  })
})
