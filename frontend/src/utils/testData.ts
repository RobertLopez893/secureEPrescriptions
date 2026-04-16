import { bytesToHex } from '@noble/hashes/utils.js';

// Llaves privadas de prueba generadas para P-256 (32 bytes en Hex)
// ¡ADVERTENCIA: Solo para desarrollo/pruebas aisladas!
export const testKeys = {
  medico: 'a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90',
  paciente: '11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff',
  farmaceutico: 'ffeeddccbbaa00998877665544332211ffeeddccbbaa00998877665544332211'
};

// Receta de prueba sin alterar
export const recetaPrueba = {
  datos: {
    paciente_id: "PAC-98765",
    medico_id: "MED-12345",
    medicamento: "Amoxicilina 500mg",
    dosis: "1 cápsula cada 8 horas",
    fecha_emision: "2026-03-26T10:00:00Z"
  },
  dispensacion: null
};