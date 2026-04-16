import { describe, it, expect } from 'vitest';
import { CryptoEngine } from '../../src/crypto';
import { SignatureModule } from '../../src/crypto/signature';
import type { DatosMedicos } from '../../src/crypto/interfaces';

// Tres actores con claves fijas de prueba
const DOCTOR_PRIV   = 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2';
const PACIENTE_PRIV = 'b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3';
const FARMACIA_PRIV = 'c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4';

const DOCTOR_PUB   = CryptoEngine.getPublicKey(DOCTOR_PRIV);
const PACIENTE_PUB = CryptoEngine.getPublicKey(PACIENTE_PRIV);
const FARMACIA_PUB = CryptoEngine.getPublicKey(FARMACIA_PRIV);

function makeDatos(): DatosMedicos {
  return {
    id_receta: 'REC-TEST-001',
    id_medico: 'DOC-001',
    id_paciente: 'PAT-001',
    fecha_emision: '2026-01-01T00:00:00.000Z',
    fecha_vencimiento: '2026-01-08T00:00:00.000Z',
    medicamentos: [{ nombre: 'Paracetamol', forma: 'Tableta', dosis: '500mg', frecuencia: '6h', duracion: '5 días' }],
  };
}

describe('CryptoEngine — Flujo E2EE completo', () => {
  const datos = makeDatos();

  // El médico emite la receta
  const paquete = CryptoEngine.emitirRecetaGlobal(
    datos, DOCTOR_PRIV, DOCTOR_PRIV, PACIENTE_PUB, FARMACIA_PUB, DOCTOR_PUB
  );

  describe('emitirRecetaGlobal', () => {
    it('retorna capsula_cifrada, iv_aes_gcm y 3 accesos', () => {
      expect(paquete.capsula_cifrada).toMatch(/^[0-9a-f]+$/);
      expect(paquete.iv_aes_gcm).toMatch(/^[0-9a-f]{24}$/);
      expect(paquete.accesos).toHaveLength(3);
    });

    it('cada acceso tiene rol, wrappedKey y nonce', () => {
      for (const acceso of paquete.accesos) {
        expect(['paciente', 'farmaceutico', 'doctor']).toContain(acceso.rol);
        expect(acceso.wrappedKey).toMatch(/^[0-9a-f]+$/);
        expect(acceso.nonce).toMatch(/^[0-9a-f]{24}$/);
      }
    });

    it('los roles son únicos en los accesos', () => {
      const roles = paquete.accesos.map(a => a.rol);
      expect(new Set(roles).size).toBe(3);
    });
  });

  describe('abrirReceta — Paciente desencripta', () => {
    it('el paciente puede abrir con su wrappedKey', () => {
      const acceso = paquete.accesos.find(a => a.rol === 'paciente')!;
      const resultado = CryptoEngine.abrirReceta(
        paquete.capsula_cifrada, paquete.iv_aes_gcm,
        acceso.wrappedKey, acceso.nonce,
        PACIENTE_PRIV, DOCTOR_PUB, DOCTOR_PUB
      );
      expect(resultado.valido).toBe(true);
      expect(resultado.contenido.datos).toEqual(datos);
    });
  });

  describe('abrirReceta — Doctor desencripta', () => {
    it('el doctor puede abrir con su wrappedKey', () => {
      const acceso = paquete.accesos.find(a => a.rol === 'doctor')!;
      const resultado = CryptoEngine.abrirReceta(
        paquete.capsula_cifrada, paquete.iv_aes_gcm,
        acceso.wrappedKey, acceso.nonce,
        DOCTOR_PRIV, DOCTOR_PUB, DOCTOR_PUB
      );
      expect(resultado.valido).toBe(true);
      expect(resultado.contenido.datos).toEqual(datos);
    });
  });

  describe('abrirReceta — Farmacia desencripta', () => {
    it('la farmacia puede abrir con su wrappedKey', () => {
      const acceso = paquete.accesos.find(a => a.rol === 'farmaceutico')!;
      const resultado = CryptoEngine.abrirReceta(
        paquete.capsula_cifrada, paquete.iv_aes_gcm,
        acceso.wrappedKey, acceso.nonce,
        FARMACIA_PRIV, DOCTOR_PUB, DOCTOR_PUB
      );
      expect(resultado.valido).toBe(true);
      expect(resultado.contenido.datos).toEqual(datos);
    });
  });

  describe('abrirReceta — Acceso no autorizado', () => {
    it('un tercero NO puede desencriptar con el wrap del paciente', () => {
      const EVE_PRIV = 'd4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5';
      const acceso = paquete.accesos.find(a => a.rol === 'paciente')!;
      expect(() => {
        CryptoEngine.abrirReceta(
          paquete.capsula_cifrada, paquete.iv_aes_gcm,
          acceso.wrappedKey, acceso.nonce,
          EVE_PRIV, DOCTOR_PUB, DOCTOR_PUB
        );
      }).toThrow();
    });
  });

  describe('abrirReceta — Integridad del ciphertext', () => {
    it('falla si la cápsula fue alterada', () => {
      const acceso = paquete.accesos.find(a => a.rol === 'paciente')!;
      const altered = paquete.capsula_cifrada.slice(0, -2) + 'ff';
      expect(() => {
        CryptoEngine.abrirReceta(
          altered, paquete.iv_aes_gcm,
          acceso.wrappedKey, acceso.nonce,
          PACIENTE_PRIV, DOCTOR_PUB, DOCTOR_PUB
        );
      }).toThrow();
    });
  });

  describe('sellar — Flujo de farmacia', () => {
    it('la farmacia sella y luego paciente/doctor pueden abrir con sello', () => {
      const accesoFarm = paquete.accesos.find(a => a.rol === 'farmaceutico')!;

      // Farmacia sella
      const sellado = CryptoEngine.sellar(
        paquete.capsula_cifrada, paquete.iv_aes_gcm,
        accesoFarm.wrappedKey, accesoFarm.nonce,
        FARMACIA_PRIV, DOCTOR_PUB, PACIENTE_PUB
      );

      // Después del sellado: solo paciente y doctor tienen acceso
      expect(sellado.accesos).toHaveLength(2);
      const rolesSellados = sellado.accesos.map(a => a.rol);
      expect(rolesSellados).toContain('paciente');
      expect(rolesSellados).toContain('doctor');
      expect(rolesSellados).not.toContain('farmaceutico');

      // Paciente abre la receta sellada (emisor del wrap ahora es farmacia)
      const accesoPac = sellado.accesos.find(a => a.rol === 'paciente')!;
      const resultado = CryptoEngine.abrirReceta(
        sellado.capsula_cifrada, sellado.iv_aes_gcm,
        accesoPac.wrappedKey, accesoPac.nonce,
        PACIENTE_PRIV, FARMACIA_PUB, DOCTOR_PUB
      );
      expect(resultado.valido).toBe(true);
      expect(resultado.contenido.sellos).toBeDefined();
      expect(resultado.contenido.sellos!.hmac_sello).toMatch(/^[0-9a-f]{64}$/);
    });

    it('rechaza sellar una receta ya sellada', () => {
      const accesoFarm = paquete.accesos.find(a => a.rol === 'farmaceutico')!;

      const sellado = CryptoEngine.sellar(
        paquete.capsula_cifrada, paquete.iv_aes_gcm,
        accesoFarm.wrappedKey, accesoFarm.nonce,
        FARMACIA_PRIV, DOCTOR_PUB, PACIENTE_PUB
      );

      // Intentar sellar de nuevo (como doctor, ya que farmacia ya no tiene acceso)
      const accesoDoc = sellado.accesos.find(a => a.rol === 'doctor')!;
      expect(() => {
        CryptoEngine.sellar(
          sellado.capsula_cifrada, sellado.iv_aes_gcm,
          accesoDoc.wrappedKey, accesoDoc.nonce,
          DOCTOR_PRIV, FARMACIA_PUB, PACIENTE_PUB
        );
      }).toThrow('RECIPE_ALREADY_SEALED');
    });
  });

  describe('abrirReceta — Verificación de firma', () => {
    it('detecta firma inválida si se altera el contenido cifrado con otro DEK', () => {
      // Crear una receta con datos alterados firmados por otro doctor
      const OTHER_PRIV = 'e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6';
      const datosAlterados = makeDatos();
      datosAlterados.id_receta = 'REC-FALSA';

      const paqueteFalso = CryptoEngine.emitirRecetaGlobal(
        datosAlterados, OTHER_PRIV, OTHER_PRIV, PACIENTE_PUB, FARMACIA_PUB, DOCTOR_PUB
      );

      // El paciente abre pero verifica contra la clave del doctor original
      const acceso = paqueteFalso.accesos.find(a => a.rol === 'paciente')!;
      const otherPub = CryptoEngine.getPublicKey(OTHER_PRIV);
      const resultado = CryptoEngine.abrirReceta(
        paqueteFalso.capsula_cifrada, paqueteFalso.iv_aes_gcm,
        acceso.wrappedKey, acceso.nonce,
        PACIENTE_PRIV, otherPub, DOCTOR_PUB // emisor es OTHER, pero verificamos contra DOCTOR
      );
      // La firma fue hecha por OTHER, no por DOCTOR, así que debe ser inválida
      expect(resultado.valido).toBe(false);
    });
  });
});
