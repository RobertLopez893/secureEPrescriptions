
// El contenido médico puro (Inmutable: Esto es lo que el médico firma)
export interface DatosMedicos {
    id_receta: string;         // Identificador único (UUID v4)
    id_medico: string;         // ID del médico emisor
    id_paciente: string;       // ID del paciente receptor
    fecha_emision: string;     // Timestamp en formato estandarizado ISO 8601
    medicamentos: Array<{
        nombre: string;
        dosis: string;
        frecuencia: string;
        duracion: string;
    }>;
    instrucciones_extra?: string; // Opcional
}

//  El Sello del Farmacéutico (Prueba de dispensación)
export interface SelloDispensacion {
    id_farmacia: string;       // ID de la farmacia que surtió el medicamento
    fecha_surtido: string;     // Timestamp exacto del surtido (ISO 8601)
    hmac_sello: string;        // Sello matemático HMAC-SHA256 (en formato Hexadecimal)
}

// El Contenedor Criptográfico Anidado (Esto es lo que se cifra con AES-GCM)
export interface RecetaContainer {
    datos: DatosMedicos;         // Los datos médicos intactos
    firma_medico: string;        // Firma ECDSA calculada estrictamente sobre 'datos'
    sellos?: SelloDispensacion; // Historial de sellos (se inicializa vacío [] al emitir)
}