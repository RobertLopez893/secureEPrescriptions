import { SignatureModule } from './signature';
import { EncryptionModule } from './encryption';
import { KeyWrapModule } from './keyWrap';
import { HmacModule } from './hmac';
import type { DatosMedicos, RecetaContainer, RecetaCifrada } from './interfaces';
import { randomBytes } from '@noble/ciphers/utils.js';

export class CryptoEngine {
  static getPublicKey(privadaHex: string): string {
    return SignatureModule.getPublicKey(privadaHex);
  }
  static getDEK(): Uint8Array {
    return randomBytes(32);
  }
  static emitirRecetaGlobal(
    datos: DatosMedicos, 
    doctorPriv: string, 
    pacientePub: string, 
    farmaciaPub: string
  ) : RecetaCifrada {
    const dek = this.getDEK();
    const firma = SignatureModule.sign(datos, doctorPriv);
    const contenedor: RecetaContainer = { datos, firma_medico: firma };
    
    const cifrado = EncryptionModule.encrypt(contenedor, dek);

    // Generamos un KeyWrap independiente para cada uno
    const kwPaciente = KeyWrapModule.wrap(dek, doctorPriv, pacientePub);
    const kwFarmacia = KeyWrapModule.wrap(dek, doctorPriv, farmaciaPub);

    return {
      ...cifrado,
      accesos: [
        { rol: 'paciente', ...kwPaciente },
        { rol: 'farmacia', ...kwFarmacia }
      ]
    };
  }
  static abrirReceta(
    capsulaHex: string, 
    ivHex: string, 
    wrappedKeyHex: string, 
    nonceKwHex: string, 
    miPriv: string, 
    emisorWrapPub: string, // <-- NUEVO: Quien generó el KeyWrap
    doctorPub: string      // <-- NUEVO: Quien firmó la receta original
  ): { valido: boolean; contenido: RecetaContainer } {
    // 1. Desenvolvemos usando la llave de quien nos mandó la cápsula
    const dek = KeyWrapModule.unwrap(wrappedKeyHex, nonceKwHex, miPriv, emisorWrapPub);
    const contenedor = EncryptionModule.decrypt(capsulaHex, ivHex, dek);
    // 2. Verificamos la firma usando SIEMPRE la llave del doctor
    const valido = SignatureModule.verify(contenedor.datos, contenedor.firma_medico, doctorPub);
    return { valido, contenido: contenedor };
  }


  static sellar(
    capsulaHex: string,
    ivHex: string,
    wrappedKeyHex: string,
    nonceKwHex: string,
    farmaciaPriv: string,
    doctorPub: string,
    pacientePub: string,
  ) : RecetaCifrada {
    const dek = KeyWrapModule.unwrap(wrappedKeyHex, nonceKwHex, farmaciaPriv, doctorPub);
    const contenedor = EncryptionModule.decrypt(capsulaHex, ivHex, dek);

    const fecha = new Date().toISOString();
    const hmacSello = HmacModule.generateSeal(
        `${contenedor.datos.id_receta}-${fecha}`, 
        farmaciaPriv
    );

    if (contenedor.sellos) {
      throw new Error("RECIPE_ALREADY_SEALED");
    }

    const contenedorActualizado: RecetaContainer = {
      ...contenedor,
      sellos: {
        id_farmacia: "FARM_ID_001",
        fecha_surtido: fecha,
        hmac_sello: hmacSello
      }
    };
    const nuevoCifrado = EncryptionModule.encrypt(contenedorActualizado, dek);
    const accesoPaciente = KeyWrapModule.wrap(dek, farmaciaPriv, pacientePub);
    const accesoDoctor = KeyWrapModule.wrap(dek, farmaciaPriv, doctorPub);

    return {
      ...nuevoCifrado,
      accesos: [
        { rol: 'paciente', ...accesoPaciente },
        { rol: 'doctor', ...accesoDoctor }
      ]
    };
  }
}


export * from './interfaces';