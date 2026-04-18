import { describe, it, expect } from 'vitest'
import { encodeCardQr, parseCardQr } from '../../src/utils/cardQr'

const SEED = 'a'.repeat(64)

describe('cardQr', () => {
  describe('encodeCardQr', () => {
    it('emite el formato rxpro://card/v1/<rol>/<id>/<seed> con rol en minúsculas', () => {
      const out = encodeCardQr({ rol: 'Paciente', identificador: 'GARM850315HDFNDS07', seedHex: SEED })
      expect(out).toBe(`rxpro://card/v1/paciente/GARM850315HDFNDS07/${SEED}`)
    })

    it('url-encodea identificadores con caracteres reservados', () => {
      const out = encodeCardQr({ rol: 'Medico', identificador: 'CED/4892', seedHex: SEED })
      // el '/' debe salir como %2F para no romper el parser
      expect(out).toContain('CED%2F4892')
    })

    it('rechaza semillas que no sean 64 hex chars', () => {
      expect(() => encodeCardQr({ rol: 'Medico', identificador: 'X', seedHex: 'abcd' }))
        .toThrow(/64 hex/)
      expect(() => encodeCardQr({ rol: 'Medico', identificador: 'X', seedHex: 'Z'.repeat(64) }))
        .toThrow(/64 hex/)
    })
  })

  describe('parseCardQr', () => {
    it('parsea un payload válido y normaliza rol + identificador', () => {
      const payload = `rxpro://card/v1/paciente/garm850315hdfnds07/${SEED}`
      const parsed = parseCardQr(payload)
      expect(parsed).not.toBeNull()
      expect(parsed!.rol).toBe('Paciente')
      expect(parsed!.identificador).toBe('GARM850315HDFNDS07')
      expect(parsed!.seedHex).toBe(SEED)
    })

    it('acepta variantes con acento (médico / farmacéutico)', () => {
      expect(parseCardQr(`rxpro://card/v1/médico/CED-1/${SEED}`)?.rol).toBe('Medico')
      expect(parseCardQr(`rxpro://card/v1/farmacéutico/LIC-1/${SEED}`)?.rol).toBe('Farmaceutico')
    })

    it('hace roundtrip con encodeCardQr', () => {
      const original = { rol: 'Farmaceutico' as const, identificador: 'LIC-123456', seedHex: SEED }
      const payload = encodeCardQr(original)
      const back = parseCardQr(payload)
      expect(back).toEqual(original)
    })

    it('retorna null para QR que no sean RxPro', () => {
      expect(parseCardQr('https://example.com/qr')).toBeNull()
      expect(parseCardQr('texto libre')).toBeNull()
      expect(parseCardQr('')).toBeNull()
    })

    it('retorna null si falta alguna sección', () => {
      expect(parseCardQr('rxpro://card/v1/paciente')).toBeNull()
      expect(parseCardQr('rxpro://card/v1/paciente/SOLO-ID')).toBeNull()
    })

    it('retorna null si el rol no existe', () => {
      expect(parseCardQr(`rxpro://card/v1/hacker/X/${SEED}`)).toBeNull()
    })

    it('retorna null si la semilla no es 64 hex', () => {
      expect(parseCardQr('rxpro://card/v1/paciente/ID/abcd')).toBeNull()
      expect(parseCardQr(`rxpro://card/v1/paciente/ID/${'Z'.repeat(64)}`)).toBeNull()
    })
  })
})
