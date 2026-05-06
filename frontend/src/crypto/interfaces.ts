
// El contenido médico puro (Inmutable: Esto es lo que el médico firma)
export interface Medicamento{
    nombre: string;
    dosis: string;
    forma: string;
    cantidad: string;   
    recargas: string;
    instrucciones: string;
}

export interface DatosMedicos {
    folio: string;             // Folio único de la receta (generado por el médico)
    id_medico: string;         // ID del médico emisor
    id_paciente: string;       // ID del paciente receptor
    id_farmaceutico: string;   // ID de la farmaceutico que surtira
    fecha_emision: string;     
    fecha_vencimiento: string; 
    medicamentos: Array<Medicamento>;
}

// ! Refactorizar
export interface SelloDispensacion {
    id_clinica: string;       // ID de la farmacia que surtió el medicamento
    fecha_surtido: string;     // Timestamp exacto del surtido (ISO 8601)
    estado: string;          // Estado de la receta en el momento del surtido (e.g., "surtida", "rechazada")
    hmac_sello: string;        // Sello matemático HMAC-SHA256 (en formato Hexadecimal)
}

// El Contenedor Criptográfico Anidado (Esto es lo que se cifra con AES-GCM)
export interface RecetaContainer {
    datos: DatosMedicos;         // Los datos médicos intactos
    firma_medico: string;        // Firma ECDSA calculada estrictamente sobre 'datos'
    sellos?: SelloDispensacion;  // Historial de sellos
}
export interface KeyWrapResult {
    rol: 'paciente' | 'farmaceutico' | 'doctor';
    wrappedKey: string;
    ephemeral_pub_hex: string;
}

export interface RecetaCifrada {
    capsula_cifrada: string;
    nonce: string;
    accesos: Array<KeyWrapResult>;
}
