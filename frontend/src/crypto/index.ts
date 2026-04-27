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
    doctorPub: string
  ) : RecetaCifrada {
    const dek = randomBytes(32);
    const firma = SignatureModule.sign(datos, keyPrivFirma);
    const contenedor: RecetaContainer = { datos, firma_medico: firma };
    
    const cifrado = EncryptionModule.encrypt(contenedor, dek);

    // Generamos un KeyWrap independiente para cada uno
    const kwPaciente = KeyWrapModule.wrap( dek, pacientePub,datos.id_receta+datos.id_paciente);
    const kwFarmacia = KeyWrapModule.wrap( dek, farmaceuticoPub,datos.id_receta+datos.id_farmaceutico);
    const kwDoctor = KeyWrapModule.wrap( dek, doctorPub,datos.id_receta+datos.id_medico);

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
    const contenedor = EncryptionModule.decrypt(capsulaHex, nonceHex, dek);
    
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
    contextInfo: string
  ) : RecetaCifrada {
    const dekDecipher = KeyWrapModule.unwrap(wrappedKeyHex, myPriv, ehpimeralPub, contextInfo);
    const contenedor = EncryptionModule.decrypt(capsulaHex, nonceHex, dekDecipher);

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
    const nuevoCifrado = EncryptionModule.encrypt(contenedorActualizado, dekCipher);
    
    const accesoPaciente = KeyWrapModule.wrap(dekCipher, pacientePub, contenedor.datos.id_receta+contenedor.datos.id_paciente);
    const accesoDoctor = KeyWrapModule.wrap(dekCipher, doctorPub, contenedor.datos.id_receta+contenedor.datos.id_medico);
    const accesoFarmaceutico = KeyWrapModule.wrap(dekCipher, pharmacistPub, contenedor.datos.id_receta+contenedor.datos.id_farmaceutico);

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