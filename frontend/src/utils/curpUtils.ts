// frontend/src/utils/curpUtils.ts

export interface DatosCURP {
  fechaNacimiento: string; // Formato YYYY-MM-DD
  genero: string;
  estado: string;
}

export function decodificarCURP(curp: string): DatosCURP | null {
  const curpRegex = /^[A-Z]{4}(\d{6})([HM])([A-Z]{2})[A-Z0-9]{5}$/i;
  const match = curp.toUpperCase().match(curpRegex);

  if (!match) return null; // CURP inválida o incompleta

  const fechaString = match[1]; // YYMMDD
  const generoChar = match[2];  // H o M
  const estadoChar = match[3];  // Clave del estado (ej. DF, MC, JZ)

  // 1. Extraer Fecha de Nacimiento
  const yy = parseInt(fechaString.substring(0, 2));
  const mm = fechaString.substring(2, 4);
  const dd = fechaString.substring(4, 6);
  
  // Lógica para determinar el siglo (Asumiendo que años > 30 son de 1900 y <= 30 son de 2000)
  // Nota: RENAPO usa el dígito 17 (0-9 para 1999, A-Z para 2000+) para esto, 
  // pero esta es una heurística rápida.
  const yearPrefix = yy > 30 ? '19' : '20'; 
  const fechaNacimiento = `${yearPrefix}${yy}-${mm}-${dd}`;

  // 2. Extraer Género
  const genero = generoChar === 'H' ? 'Hombre' : 'Mujer';

  return {
    fechaNacimiento,
    genero,
    estado: estadoChar
  };
}
