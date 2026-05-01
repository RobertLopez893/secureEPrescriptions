import { SignatureModule } from './signature';
import { EncryptionModule } from './encryption';
import { KeyWrapModule } from './keyWrap';
import { HmacModule } from './hmac';
import { CryptoContextFactory } from './contextFactory';
import type { DatosMedicos, RecetaContainer, RecetaCifrada, KeyWrapResult } from './interfaces';
import { randomBytes } from '@noble/ciphers/utils.js';

interface InfoAcces {
  paciente: string;
  doctor: string;
  farmaceutico: string;
}

export class CryptoEngine {

  static emitirRecetaGlobal(
    datos: DatosMedicos, 
    keyPrivFirma: string,
    pacientePub: string, 
    farmaceuticoPub: string,
    doctorPub: string,
    idFarmaceutico: string,
  ) : RecetaCifrada {
    const dek = randomBytes(32);
    const firma = SignatureModule.sign(datos, keyPrivFirma);
    const contenedor: RecetaContainer = { datos, firma_medico: firma };
    
    const aadBytes = CryptoContextFactory.buildAAD(datos.id_receta, datos.id_medico, datos.id_paciente);
    const cifrado = EncryptionModule.encrypt(contenedor, dek,aadBytes);



    const ctxPaciente = CryptoContextFactory.buildHKDFContext(datos.id_receta, datos.id_paciente);
    const ctxFarmacia = CryptoContextFactory.buildHKDFContext(datos.id_receta, idFarmaceutico);
    const ctxDoctor   = CryptoContextFactory.buildHKDFContext(datos.id_receta, datos.id_medico);
    // Generamos un KeyWrap independiente para cada uno
    const kwPaciente = KeyWrapModule.wrap( dek, pacientePub,ctxPaciente);
    const kwFarmacia = KeyWrapModule.wrap( dek, farmaceuticoPub,ctxFarmacia);
    const kwDoctor = KeyWrapModule.wrap( dek, doctorPub,ctxDoctor);

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
    payload: RecetaCifrada,
    rol: 'paciente' | 'farmaceutico' | 'doctor', 
    miPriv: string, 
    signaturePub: string,
    idReceta: string,
    idMedico: string,
    idPaciente: string,
    myId: string
  ): { valido: boolean; contenido: RecetaContainer } {
    const acceso = payload.accesos.find(a => a.rol === rol);
    if(!acceso) throw new Error('NO_ACCESS_FOR_ROLE');
    // 1. Desenvolvemos usando la llave de quien nos mandó la cápsula
    const hdfkContext = CryptoContextFactory.buildHKDFContext(idReceta,myId);
    const dek = KeyWrapModule.unwrap(acceso.wrappedKey, miPriv, acceso.ephemeralPubHex, hdfkContext);
    const aad = CryptoContextFactory.buildAAD(idReceta, idMedico,idPaciente); // El AAD se construye con los IDs principales, pero para ver la receta no necesitamos el ID del médico ni del paciente, solo el de la receta. Se podría mejorar esto.
    const contenedor = EncryptionModule.decrypt(payload.capsula_cifrada, payload.iv_aes_gcm, dek, aad);
    
    const valido = SignatureModule.verify(contenedor.datos, contenedor.firma_medico, signaturePub);
    return { valido, contenido: contenedor };
  }

  // ! Refactorizar se ve feo
  static sellar( 
    Contenedor: RecetaContainer,
    keyPrivSello: string,
    sealInfo: { estado: string; id_clinica: string },
    idReceta: string,
    idMedico: string,
    idPaciente: string,
    pacientePub: string, 
    farmaceuticoPub: string,
    doctorPub: string,
    idFarmaceutico: string
  ) : RecetaCifrada {
    if (Contenedor.sellos) {
      throw new Error("RECIPE_ALREADY_SEALED");
    }
    const fecha = new Date().toISOString();

    const seal=CryptoContextFactory.buildSealMessage(idReceta, sealInfo.estado, sealInfo.id_clinica, fecha);
    const hmacSello = HmacModule.generateSeal(seal, keyPrivSello);


    const contenedorActualizado: RecetaContainer = {
      ...Contenedor,
      sellos: {
        id_clinica: sealInfo.id_clinica,
        fecha_surtido: fecha,
        estado: sealInfo.estado,
        hmac_sello: hmacSello
      }
    };

    const dekCipher = randomBytes(32);
    const aad = CryptoContextFactory.buildAAD(idReceta, idMedico, idPaciente);
    const nuevoCifrado = EncryptionModule.encrypt(contenedorActualizado, dekCipher, aad);
 
    
    const ctxPaciente = CryptoContextFactory.buildHKDFContext(idReceta, idPaciente);
    const ctxFarmacia = CryptoContextFactory.buildHKDFContext(idReceta, idFarmaceutico);
    const ctxDoctor   = CryptoContextFactory.buildHKDFContext(idReceta, idMedico);

    const accesoPaciente = KeyWrapModule.wrap(dekCipher, pacientePub, ctxPaciente);
    const accesoDoctor = KeyWrapModule.wrap(dekCipher, doctorPub, ctxDoctor);
    const accesoFarmaceutico = KeyWrapModule.wrap(dekCipher, farmaceuticoPub, ctxFarmacia);

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