import { describe, it, expect, beforeEach, vi } from 'vitest'

// --- Mocks de las dependencias de pharmacyReceta.ts -------------------------
// La SUT importa './api.ts', '../crypto/index.ts' y './userKeys.ts'. Vitest
// resuelve estos specifiers al mismo módulo absoluto que mockeamos aquí.
vi.mock('../../src/utils/api.ts', () => ({
  getSession: vi.fn(),
  Api: {
    obtenerRecetaInfo: vi.fn(),
    obtenerRecetaCripto: vi.fn(),
    obtenerLlavePublica: vi.fn(),
  },
}))
vi.mock('../../src/crypto/index.ts', () => ({
  CryptoEngine: { abrirReceta: vi.fn() },
}))
vi.mock('../../src/utils/userKeys.ts', () => ({
  getUserPrivKeyHex: vi.fn(),
}))

import { cargarRecetaValidada, RecetaValidationError, mensajeReceta } from '../../src/utils/pharmacyReceta'
import { Api, getSession } from '../../src/utils/api'
import { CryptoEngine } from '../../src/crypto/index'
import { getUserPrivKeyHex } from '../../src/utils/userKeys'

const SESSION = { id: 7, correo: 'jefe@farmacia', role: 'Farmaceutico' }

function recetaInfoBase(): any {
  return {
    estado: 'emitida',
    vencida: false,
    id_farmaceutico: 7, // == SESSION.id  → no dispara NO_ASIGNADA
    id_medico: 3,
    id_paciente: 9,
    folio: 'FOLIO-001',
    paciente: { nombre_completo: 'Ana Paciente' },
    medico: { nombre_completo: 'Dr. House' },
  }
}

/** Deja todos los mocks en el camino feliz; cada test rompe lo que necesita. */
function setHappyPath() {
  ;(getSession as any).mockReturnValue(SESSION)
  ;(Api.obtenerRecetaInfo as any).mockResolvedValue(recetaInfoBase())
  ;(getUserPrivKeyHex as any).mockReturnValue('deadbeef')
  ;(Api.obtenerRecetaCripto as any).mockResolvedValue({ capsula: 'x' })
  ;(Api.obtenerLlavePublica as any).mockResolvedValue({ llave_publica: 'PUB-DOC' })
  ;(CryptoEngine.abrirReceta as any).mockReturnValue({
    valido: true,
    contenido: { datos: { folio: 'FOLIO-001' }, sellos: undefined },
  })
}

async function expectCode(code: string) {
  await expect(cargarRecetaValidada(1)).rejects.toMatchObject({
    name: 'RecetaValidationError',
    code,
    message: mensajeReceta(code as any),
  })
}

describe('cargarRecetaValidada — compuertas de bloqueo', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    setHappyPath()
  })

  it('SIN_SESION cuando no hay sesión de farmacéutico', async () => {
    ;(getSession as any).mockReturnValue(null)
    await expectCode('SIN_SESION')
  })

  it('YA_SURTIDA cuando la receta ya fue surtida', async () => {
    ;(Api.obtenerRecetaInfo as any).mockResolvedValue({ ...recetaInfoBase(), estado: 'surtida' })
    await expectCode('YA_SURTIDA')
  })

  it('VENCIDA cuando recetaInfo.vencida === true', async () => {
    ;(Api.obtenerRecetaInfo as any).mockResolvedValue({ ...recetaInfoBase(), vencida: true })
    await expectCode('VENCIDA')
  })

  it('NO_ASIGNADA cuando el farmacéutico logueado no es el asignado', async () => {
    ;(Api.obtenerRecetaInfo as any).mockResolvedValue({ ...recetaInfoBase(), id_farmaceutico: 999 })
    await expectCode('NO_ASIGNADA')
  })

  it('SIN_LLAVE cuando no hay llave recipes en sesión', async () => {
    ;(getUserPrivKeyHex as any).mockReturnValue(null)
    await expectCode('SIN_LLAVE')
  })

  it('DESCIFRADO cuando abrirReceta lanza (acceso/cápsula alterada)', async () => {
    ;(CryptoEngine.abrirReceta as any).mockImplementation(() => { throw new Error('NO_ACCESS_FOR_ROLE') })
    await expectCode('DESCIFRADO')
  })

  it('FIRMA_INVALIDA cuando la firma del médico no verifica', async () => {
    ;(CryptoEngine.abrirReceta as any).mockReturnValue({
      valido: false,
      contenido: { datos: { folio: 'FOLIO-001' } },
    })
    await expectCode('FIRMA_INVALIDA')
  })

  it('YA_SELLADA cuando el contenedor ya tiene sello de dispensación', async () => {
    ;(CryptoEngine.abrirReceta as any).mockReturnValue({
      valido: true,
      contenido: { datos: { folio: 'FOLIO-001' }, sellos: { hmac_sello: 'abc' } },
    })
    await expectCode('YA_SELLADA')
  })
})

describe('cargarRecetaValidada — camino feliz', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    setHappyPath()
  })

  it('devuelve recetaInfo, payload y contenedor cuando todo valida', async () => {
    const out = await cargarRecetaValidada(1)
    expect(out.recetaInfo.folio).toBe('FOLIO-001')
    expect(out.contenedor.datos.folio).toBe('FOLIO-001')
    expect(out.payload).toEqual({ capsula: 'x' })
  })

  it('pide la pública de FIRMA del médico con responsabilidad "firmas"', async () => {
    await cargarRecetaValidada(1)
    expect(Api.obtenerLlavePublica).toHaveBeenCalledWith(3, 'firmas')
  })

  it('pasa los IDs prefijados y el folio a CryptoEngine.abrirReceta', async () => {
    await cargarRecetaValidada(1)
    expect(CryptoEngine.abrirReceta).toHaveBeenCalledWith(
      { capsula: 'x' },
      'farmaceutico',
      'deadbeef',
      'PUB-DOC',
      'DOC-3',
      'USR-9',
      'FAR-7',
      'FOLIO-001',
    )
  })

  it('lanza RecetaValidationError (no Error genérico) para discriminar en la UI', async () => {
    ;(getSession as any).mockReturnValue(null)
    await expect(cargarRecetaValidada(1)).rejects.toBeInstanceOf(RecetaValidationError)
  })
})
