import { SignatureModule } from './signature';
import { EncryptionModule } from './encryption';
import { KeyWrapModule } from './keyWrap';
import { HmacModule } from './hmac';
import type { DatosMedicos, RecetaContainer, RecetaCifrada } from './interfaces';
import { randomBytes } from '@noble/ciphers/utils.js';

export class CryptoEngine {

  static emitirRecetaGlobal(
    datos: DatosMedicos, 
    keyPrivFirma: string,
    pacientePub: string, 
    farmaceuticoPub: string,
    doctorPub: string,
    contextInfo: string,
    AAD: string
  ) : RecetaCifrada {
    const dek = randomBytes(32);
    const firma = SignatureModule.sign(datos, keyPrivFirma);
    const contenedor: RecetaContainer = { datos, firma_medico: firma };
    
    const cifrado = EncryptionModule.encrypt(contenedor, dek,AAD);

    // Generamos un KeyWrap independiente para cada uno
    const kwPaciente = KeyWrapModule.wrap( dek, pacientePub,contextInfo);
    const kwFarmacia = KeyWrapModule.wrap( dek, farmaceuticoPub,contextInfo);
    const kwDoctor = KeyWrapModule.wrap( dek, doctorPub,contextInfo);

    return {
      ...cifrado,
      accesos: [
        { rol: 'paciente', ...kwPaciente },
        { rol: 'farmaceutico', ...kwFarmacia },
        { rol: 'doctor', ...kwDoctor }
      ]
    };
  }
  static abrirReceta(
    capsulaHex: string, 
    nonceHex: string, 
    wrappedKeyHex: string, 
    ephemeralPubHex: string, 
    miPriv: string, 
    signaturePub: string,
    ContextInfo: string,
  ): { valido: boolean; contenido: RecetaContainer } {
    // 1. Desenvolvemos usando la llave de quien nos mandó la cápsula
    const dek = KeyWrapModule.unwrap(wrappedKeyHex, miPriv, ephemeralPubHex,ContextInfo);
    const contenedor = EncryptionModule.decrypt(capsulaHex, nonceHex, dek,ContextInfo);
    
    const valido = SignatureModule.verify(contenedor.datos, contenedor.firma_medico, signaturePub);
    return { valido, contenido: contenedor };
  }


  static sellar(
    capsulaHex: string,
    nonceHex: string,
    wrappedKeyHex: string,
    myPriv: string,
    ehpimeralPub: string,
    pacientePub: string,
    pharmacistPub: string,
    doctorPub: string,
    AAD: string,
    contextInfo: string
  ) : RecetaCifrada {
    const dekDecipher = KeyWrapModule.unwrap(wrappedKeyHex, myPriv, ehpimeralPub, contextInfo);
    const contenedor = EncryptionModule.decrypt(capsulaHex, nonceHex, dekDecipher, AAD);

    const fecha = new Date().toISOString();
    const hmacSello = HmacModule.generateSeal(
        `${contenedor.datos.id_receta}-${fecha}`, 
        myPriv
    );

    if (contenedor.sellos) {
      throw new Error("RECIPE_ALREADY_SEALED");
    }

    const contenedorActualizado: RecetaContainer = {
      ...contenedor,
      sellos: {
        id_clinica: "FARM_ID_001",
        fecha_surtido: fecha,
        hmac_sello: hmacSello
      }
    };
    const dekCipher = randomBytes(32);
    const nuevoCifrado = EncryptionModule.encrypt(contenedorActualizado, dekCipher,AAD);
    
    const accesoPaciente = KeyWrapModule.wrap(dekCipher, pacientePub, contextInfo);
    const accesoDoctor = KeyWrapModule.wrap(dekCipher, doctorPub, contextInfo);
    const accesoFarmaceutico = KeyWrapModule.wrap(dekCipher, pharmacistPub, contextInfo);

    return {
      ...nuevoCifrado,
      accesos: [
        { rol: 'paciente', ...accesoPaciente },
        { rol: 'doctor', ...accesoDoctor },
        { rol: 'farmaceutico', ...accesoFarmaceutico }
      ]
    };
  }
}


export * from './interfaces';