import { SignatureModule } from './signature';
import { EncryptionModule } from './encryption';
import { KeyWrapModule } from './keyWrap';
import { HmacModule } from './hmac';
import { CryptoContextFactory } from './contextFactory';
import type { DatosMedicos, RecetaContainer, RecetaCifrada, KeyWrapResult } from './interfaces';
import { randomBytes } from '@noble/ciphers/utils.js';


export class CryptoEngine {
  static getPublicKey(privateKey: string): string {
    return SignatureModule.getPublicKey(privateKey);
  } 

  static emitirRecetaGlobal(
    datos: DatosMedicos, 
    keyPrivFirma: string,
    pacientePubDH: string,  
    farmaceuticoPubDH: string,
    doctorPubDH: string,
  ) : RecetaCifrada {

    const dek = randomBytes(32);
    const firma = SignatureModule.sign(datos, keyPrivFirma);
    
    const contenedor: RecetaContainer = { datos, firma_medico: firma};
    
    const aadBytes = CryptoContextFactory.buildAAD(datos.folio, datos.id_medico, datos.id_paciente);
    const cifrado = EncryptionModule.encrypt(contenedor, dek,aadBytes);



    const ctxPaciente = CryptoContextFactory.buildHKDFContext(datos.folio, datos.id_paciente);
    const ctxFarmacia = CryptoContextFactory.buildHKDFContext(datos.folio, datos.id_farmaceutico);
    const ctxDoctor   = CryptoContextFactory.buildHKDFContext(datos.folio, datos.id_medico);
    // Generamos un KeyWrap independiente para cada uno
    const kwPaciente = KeyWrapModule.wrap( 'paciente',dek, pacientePubDH,ctxPaciente);
    const kwFarmaceutico = KeyWrapModule.wrap( 'farmaceutico',dek, farmaceuticoPubDH,ctxFarmacia);
    const kwDoctor = KeyWrapModule.wrap( 'doctor',dek, doctorPubDH ,ctxDoctor);

    return {
      ...cifrado,
      accesos: [kwPaciente, kwFarmaceutico, kwDoctor]
    };
  }
  
  static abrirReceta(
    payload: RecetaCifrada,
    rol: 'paciente' | 'farmaceutico' | 'doctor', 
    myPrivDH: string, 
    doctorPubFirma: string,
    idMedico: string,
    idPaciente: string,
    idFarmaceutico: string,
    folio: string
  ): { valido: boolean; contenido: RecetaContainer } {
    const acceso = payload.accesos.find(a => a.rol === rol);
    if(!acceso) throw new Error('NO_ACCESS_FOR_ROLE');
    const myId =(rol === 'paciente')? idPaciente : (rol === 'doctor')? idMedico : idFarmaceutico; // El ID de la farmacia no está en la receta, así que se asume que es el mismo que el del médico pero con prefijo diferente. Esto se podría mejorar incluyendo el ID de la farmacia en la receta.
    // 1. Desenvolvemos usando la llave de quien nos mandó la cápsula
    const hdfkContext = CryptoContextFactory.buildHKDFContext(folio,myId);
    const dek = KeyWrapModule.unwrap(acceso.wrappedKey, myPrivDH, acceso.ephemeral_pub_hex, hdfkContext);
    const aad = CryptoContextFactory.buildAAD(folio, idMedico,idPaciente); // El AAD se construye con los IDs principales, pero para ver la receta no necesitamos el ID del médico ni del paciente, solo el de la receta. Se podría mejorar esto.
    const contenedor = EncryptionModule.decrypt(payload.capsula_cifrada, payload.nonce, dek, aad);
    
    const valido = SignatureModule.verify(contenedor.datos, contenedor.firma_medico, doctorPubFirma);
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

    const accesoPaciente = KeyWrapModule.wrap('paciente', dekCipher, pacientePub, ctxPaciente);
    const accesoDoctor = KeyWrapModule.wrap('doctor', dekCipher, doctorPub, ctxDoctor);
    const accesoFarmaceutico = KeyWrapModule.wrap('farmaceutico', dekCipher, farmaceuticoPub, ctxFarmacia);

    return {
      ...nuevoCifrado,
      accesos: [accesoPaciente, accesoDoctor, accesoFarmaceutico]
    };
  }
}


export * from './interfaces';