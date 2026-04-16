/**
 * src/crypto/index.ts
 * Orquestador Global del Motor Criptográfico con KeyWrap (E2EE)
 */
import { SignatureModule } from './signature';
import { EncryptionModule } from './encryption';
import { KeyWrapModule } from './keyWrap';
import { HmacModule } from './hmac';
import type { DatosMedicos, RecetaContainer } from './interfaces';

export class CryptoEngine {
  
  /**
   * 1. FLUJO DE EMISIÓN (Médico)
   * Firma, Cifra y además Envuelve la DEK para el paciente.
   */
  static async emitirYEnvolverReceta(
    datos: DatosMedicos, 
    doctorPrivateKey: string, 
    doctorPublicKey: string,
    pacientePublicKey: string,
    farmaceuticoPublicKey: string,
    dek: Uint8Array
  ) {
    // A. Firmar
    const firma = SignatureModule.sign(datos, doctorPrivateKey);

    // B. Encapsular
    const contenedor: RecetaContainer = {
        datos,
        firma_medico: firma
    };

    // C. Cifrar Datos (AES-GCM)
    const cifrado = EncryptionModule.encrypt(contenedor, dek);

    // D. Envolver la DEK para cada rol (KeyWrap vía ECDH)
    // Esto genera una "Wrapped Key" que solo el destinatario puede abrir.
    const dekMedico = KeyWrapModule.wrap(dek, doctorPrivateKey, doctorPublicKey);
    const dekPaciente = KeyWrapModule.wrap(dek, doctorPrivateKey, pacientePublicKey);
    const dekFarmaceutico = KeyWrapModule.wrap(dek, doctorPrivateKey, farmaceuticoPublicKey);

    return {
      ...cifrado,
      capsula: cifrado.ciphertext,
      iv: cifrado.iv,
      dek_medico: dekMedico,
      dek_paciente: dekPaciente,
      dek_farmaceutico: dekFarmaceutico
    };
  }

  /**
   * 2. FLUJO DE APERTURA (Paciente / Farmacia)
   * Primero desenvuelve la llave y luego descifra la receta.
   */
  static async desencapsularReceta(
    capsulaHex: string,
    ivHex: string,
    wrappedKeyHex: string,
    nonceKwHex: string,
    miPrivateKey: string,
    otraPublicKey: string // La pública de quien envió la llave
  ): Promise<{ valido: boolean; contenido: RecetaContainer }> {
    
    // A. Desenvolver la DEK (ECDH)
    // Nota: Necesitarás implementar 'unwrap' en tu KeyWrapModule 
    // usando sharedSecret = p256.getSharedSecret(miPrivada, otraPublica)
    // Por ahora, asumimos que recuperamos la DEK:
    const dek = await KeyWrapModule.unwrap(wrappedKeyHex, nonceKwHex, miPrivateKey, otraPublicKey);

    // B. Descifrar Contenedor
    const contenedor = EncryptionModule.decrypt(capsulaHex, ivHex, dek);

    // C. Verificar Firma (Siempre se verifica el origen)
    const esValida = SignatureModule.verify(
        contenedor.datos, 
        contenedor.firma_medico, 
        otraPublicKey // Pública del médico
    );

    return {
        valido: esValida,
        contenido: contenedor
    };
  }

  /**
   * 3. FLUJO DE SELLADO (Farmacia)
   * Firma del surtido y re-cifrado.
   */
  static async sellarDispensacion(
    contenedor: RecetaContainer,
    idFarmacia: string,
    secretFarmacia: string,
    dek: Uint8Array
  ) {
    const fecha = new Date().toISOString();
    const dataToSeal = `${contenedor.datos.id_receta}-${fecha}`;
    const hmac = HmacModule.generateSeal(dataToSeal, secretFarmacia);

    const contenedorSellado: RecetaContainer = {
        ...contenedor,
        sellos: {
            id_farmacia: idFarmacia,
            fecha_surtido: fecha,
            hmac_sello: hmac
        }
    };

    return EncryptionModule.encrypt(contenedorSellado, dek);
  }
}

export * from './interfaces';