// frontend/test/crypto/engine.test.ts
import { describe, it, expect } from 'vitest';
import { CryptoEngine } from '../../src/crypto/index';
import { p256 } from '@noble/curves/nist.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import type { DatosMedicos } from '../../src/crypto/interfaces';

// Helper para generar llaves públicas válidas a partir del Hex privado
function getPublicKeyHex(privKeyHex: string): string {
  return bytesToHex(p256.getPublicKey(hexToBytes(privKeyHex), false));
}

// Tres actores con claves fijas de prueba (64 chars hex)
const DOCTOR_PRIV   = 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2';
const PACIENTE_PRIV = 'b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3';
const FARMACIA_PRIV = 'c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4';
const EVE_PRIV      = 'd4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5';

const DOCTOR_PUB   = getPublicKeyHex(DOCTOR_PRIV);
const PACIENTE_PUB = getPublicKeyHex(PACIENTE_PRIV);
const FARMACIA_PUB = getPublicKeyHex(FARMACIA_PRIV);
const EVE_PUB      = getPublicKeyHex(EVE_PRIV);

function makeDatos(): DatosMedicos {
  return {
    id_receta: 'REC-TEST-001',
    id_medico: 'DOC-001',
    id_paciente: 'PAT-001',
    id_farmaceutico: 'FARM-001',
    fecha_emision: '2026-01-01T00:00:00.000Z',
    fecha_vencimiento: '2026-01-08T00:00:00.000Z',
    medicamentos: [{ nombre: 'Paracetamol', forma: 'Tableta', dosis: '500mg', frecuencia: '6h', duracion: '5 días' }],
  };
}

describe('CryptoEngine — Flujo E2EE Completo', () => {
  const datos = makeDatos();

  // El médico emite la receta
  const paquete = CryptoEngine.emitirRecetaGlobal(
    datos, DOCTOR_PRIV, PACIENTE_PUB, FARMACIA_PUB, DOCTOR_PUB
  );

  describe('1. emitirRecetaGlobal', () => {
    it('retorna capsula_cifrada, iv_aes_gcm y exactamente 3 accesos empaquetados', () => {
      expect(paquete.capsula_cifrada).toMatch(/^[0-9a-f]+$/);
      expect(paquete.iv_aes_gcm).toMatch(/^[0-9a-f]{24}$/);
      expect(paquete.accesos).toHaveLength(3);
    });

    it('cada acceso tiene rol, wrappedKey y ephemeralPubHex', () => {
      for (const acceso of paquete.accesos) {
        expect(['paciente', 'farmaceutico', 'doctor']).toContain(acceso.rol);
        expect(acceso.wrappedKey).toMatch(/^[0-9a-f]+$/);
        expect(acceso.ephemeralPubHex).toMatch(/^[0-9a-f]+$/);
      }
    });

    it('los roles son únicos en el array de accesos', () => {
      const roles = paquete.accesos.map(a => a.rol);
      expect(new Set(roles).size).toBe(3);
    });
  });

  describe('2. abrirReceta — Flujos Exitosos', () => {
    it('el PACIENTE puede abrir con su wrappedKey y ContextInfo correctos', () => {
      const acceso = paquete.accesos.find(a => a.rol === 'paciente')!;
      const contextInfo = datos.id_receta + datos.id_paciente;
      const resultado = CryptoEngine.abrirReceta(
        paquete.capsula_cifrada, paquete.iv_aes_gcm,
        acceso.wrappedKey, acceso.ephemeralPubHex,
        PACIENTE_PRIV, DOCTOR_PUB, contextInfo
      );
      expect(resultado.valido).toBe(true);
      expect(resultado.contenido.datos).toEqual(datos);
    });

    it('el DOCTOR puede abrir con su wrappedKey y ContextInfo correctos', () => {
      const acceso = paquete.accesos.find(a => a.rol === 'doctor')!;
      const contextInfo = datos.id_receta + datos.id_medico;
      const resultado = CryptoEngine.abrirReceta(
        paquete.capsula_cifrada, paquete.iv_aes_gcm,
        acceso.wrappedKey, acceso.ephemeralPubHex,
        DOCTOR_PRIV, DOCTOR_PUB, contextInfo
      );
      expect(resultado.valido).toBe(true);
      expect(resultado.contenido.datos).toEqual(datos);
    });

    it('la FARMACIA puede abrir con su wrappedKey y ContextInfo correctos', () => {
      const acceso = paquete.accesos.find(a => a.rol === 'farmaceutico')!;
      const contextInfo = datos.id_receta + datos.id_farmaceutico;
      const resultado = CryptoEngine.abrirReceta(
        paquete.capsula_cifrada, paquete.iv_aes_gcm,
        acceso.wrappedKey, acceso.ephemeralPubHex,
        FARMACIA_PRIV, DOCTOR_PUB, contextInfo
      );
      expect(resultado.valido).toBe(true);
      expect(resultado.contenido.datos).toEqual(datos);
    });
  });

  describe('3. abrirReceta — Control de Accesos y Errores (ContextInfo y Llaves)', () => {
    it('falla si un rol intenta usar el wrap de otro (Validación de ContextInfo del HKDF)', () => {
      const accesoPac = paquete.accesos.find(a => a.rol === 'paciente')!;
      // El paciente intenta descifrar pero enviando el contexto del doctor
      const malContextInfo = datos.id_receta + datos.id_medico; 
      
      expect(() => {
        CryptoEngine.abrirReceta(
          paquete.capsula_cifrada, paquete.iv_aes_gcm,
          accesoPac.wrappedKey, accesoPac.ephemeralPubHex,
          PACIENTE_PRIV, DOCTOR_PUB, malContextInfo
        );
      }).toThrow(); // AES-KW lanzará error de integridad
    });

    it('un atacante (EVE) NO puede desencriptar incluso si intercepta la cápsula', () => {
      const acceso = paquete.accesos.find(a => a.rol === 'paciente')!;
      const contextInfo = datos.id_receta + datos.id_paciente;
      expect(() => {
        CryptoEngine.abrirReceta(
          paquete.capsula_cifrada, paquete.iv_aes_gcm,
          acceso.wrappedKey, acceso.ephemeralPubHex,
          EVE_PRIV, DOCTOR_PUB, contextInfo
        );
      }).toThrow(); // Falla el unwrap porque su secreto ECDH no coincide
    });

    it('detecta y reporta firma de médico inválida (valido: false) sin arrojar excepción', () => {
      const acceso = paquete.accesos.find(a => a.rol === 'paciente')!;
      const contextInfo = datos.id_receta + datos.id_paciente;
      const resultado = CryptoEngine.abrirReceta(
        paquete.capsula_cifrada, paquete.iv_aes_gcm,
        acceso.wrappedKey, acceso.ephemeralPubHex,
        PACIENTE_PRIV, EVE_PUB, contextInfo // Pasamos la llave de EVE para verificar la firma
      );
      expect(resultado.valido).toBe(false); // La firma no coincide con EVE_PUB
      expect(resultado.contenido.datos).toBeDefined(); // Aún puede leer el contenedor
    });
  });

  describe('4. sellar — Flujo de Farmacia y Mutación de Receta', () => {
    it('la farmacia aplica su sello, regenera el cifrado y renueva accesos', () => {
      const accesoFarm = paquete.accesos.find(a => a.rol === 'farmaceutico')!;
      const contextFarm = datos.id_receta + datos.id_farmaceutico;

      const sellado = CryptoEngine.sellar(
        paquete.capsula_cifrada, paquete.iv_aes_gcm,
        accesoFarm.wrappedKey, FARMACIA_PRIV, accesoFarm.ephemeralPubHex,
        PACIENTE_PUB, FARMACIA_PUB, DOCTOR_PUB, contextFarm
      );

      // Verificamos nueva estructura
      expect(sellado.capsula_cifrada).not.toBe(paquete.capsula_cifrada);
      expect(sellado.accesos).toHaveLength(3); // Tu implementacion de index.ts emite 3 accesos de nuevo

      // El paciente debe poder abrir el nuevo paquete
      const accesoPac = sellado.accesos.find(a => a.rol === 'paciente')!;
      const contextPac = datos.id_receta + datos.id_paciente;
      
      const resultado = CryptoEngine.abrirReceta(
        sellado.capsula_cifrada, sellado.iv_aes_gcm,
        accesoPac.wrappedKey, accesoPac.ephemeralPubHex,
        PACIENTE_PRIV, DOCTOR_PUB, contextPac
      );

      expect(resultado.valido).toBe(true); // La firma del doctor intacta
      expect(resultado.contenido.sellos).toBeDefined(); // ¡El sello de farmacia está incrustado!
      expect(resultado.contenido.sellos!.hmac_sello).toMatch(/^[0-9a-f]+$/);
      expect(resultado.contenido.sellos!.id_clinica).toBe('FARM_ID_001');
    });

    it('rechaza categóricamente intentar sellar una receta que ya está sellada', () => {
      const accesoFarm = paquete.accesos.find(a => a.rol === 'farmaceutico')!;
      const contextFarm = datos.id_receta + datos.id_farmaceutico;

      const primerSello = CryptoEngine.sellar(
        paquete.capsula_cifrada, paquete.iv_aes_gcm,
        accesoFarm.wrappedKey, FARMACIA_PRIV, accesoFarm.ephemeralPubHex,
        PACIENTE_PUB, FARMACIA_PUB, DOCTOR_PUB, contextFarm
      );

      // Intentar aplicar un segundo sello extrayendo el nuevo acceso de farmacia
      const nuevoAccesoFarm = primerSello.accesos.find(a => a.rol === 'farmaceutico')!;
      
      expect(() => {
        CryptoEngine.sellar(
          primerSello.capsula_cifrada, primerSello.iv_aes_gcm,
          nuevoAccesoFarm.wrappedKey, FARMACIA_PRIV, nuevoAccesoFarm.ephemeralPubHex,
          PACIENTE_PUB, FARMACIA_PUB, DOCTOR_PUB, contextFarm
        );
      }).toThrow('RECIPE_ALREADY_SEALED');
    });
  });
});