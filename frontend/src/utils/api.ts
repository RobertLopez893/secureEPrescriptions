// src/utils/api.ts
// Cliente API centralizado para comunicarse con el backend FastAPI.
// Mantiene el estado de diseño del frontend intacto: esta capa es puramente
// transport/serialización y el UI sólo importa las funciones nombradas.

// ---------------------------------------------------------------------------
// Configuración base
// ---------------------------------------------------------------------------

/**
 * Resuelve la URL base de la API. En Astro/Vite las variables con prefijo
 * PUBLIC_ están expuestas al bundle cliente vía import.meta.env.
 * Fallback a http://localhost:8000 para desarrollo en host directo.
 */
function resolveApiBase(): string {
  try {
    // @ts-ignore - import.meta.env existe en Astro/Vite
    const fromEnv = import.meta?.env?.PUBLIC_API_URL as string | undefined;
    if (fromEnv && fromEnv.trim().length > 0) return fromEnv.replace(/\/$/, '');
  } catch { /* noop: entornos sin import.meta */ }
  return 'http://localhost:8000';
}

export const API_BASE = resolveApiBase();

// ---------------------------------------------------------------------------
// Storage keys (para JWT + sesión)
// ---------------------------------------------------------------------------
const TOKEN_KEY = 'rxpro_token';
const SESSION_KEY = 'rxpro_session';

export interface SessionData {
  id: number;
  correo: string;
  role: string;           // "Medico" | "Paciente" | "Farmaceutico" | "Administrador"
  nombre?: string;
}

export function saveSession(token: string, session: SessionData): void {
  if (typeof sessionStorage === 'undefined') return;
  sessionStorage.setItem(TOKEN_KEY, token);
  sessionStorage.setItem(SESSION_KEY, JSON.stringify(session));
}

export function getToken(): string | null {
  if (typeof sessionStorage === 'undefined') return null;
  return sessionStorage.getItem(TOKEN_KEY);
}

export function getSession(): SessionData | null {
  if (typeof sessionStorage === 'undefined') return null;
  const raw = sessionStorage.getItem(SESSION_KEY);
  if (!raw) return null;
  try { return JSON.parse(raw) as SessionData; } catch { return null; }
}

export function clearSession(): void {
  if (typeof sessionStorage === 'undefined') return;
  sessionStorage.removeItem(TOKEN_KEY);
  sessionStorage.removeItem(SESSION_KEY);
}

/**
 * Decodifica el payload de un JWT sin verificar firma (eso lo hace el backend).
 * Solo se usa para obtener id/role/correo del token recién emitido.
 */
export function decodeJwtPayload(token: string): Record<string, any> | null {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const payload = parts[1].replace(/-/g, '+').replace(/_/g, '/');
    const padded = payload + '='.repeat((4 - payload.length % 4) % 4);
    const decoded = atob(padded);
    return JSON.parse(decoded);
  } catch { return null; }
}

// ---------------------------------------------------------------------------
// Fetch helper
// ---------------------------------------------------------------------------

export class ApiError extends Error {
  status: number;
  detail: string;
  constructor(status: number, detail: string) {
    super(detail);
    this.status = status;
    this.detail = detail;
  }
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const url = `${API_BASE}${path}`;
  const headers = new Headers(init.headers || {});
  if (!headers.has('Content-Type') && init.body) {
    headers.set('Content-Type', 'application/json');
  }
  const token = getToken();
  if (token && !headers.has('Authorization')) {
    headers.set('Authorization', `Bearer ${token}`);
  }

  let res: Response;
  try {
    res = await fetch(url, { ...init, headers });
  } catch (e: any) {
    throw new ApiError(0, `No se pudo contactar al servidor (${e?.message ?? 'red'})`);
  }

  if (!res.ok) {
    let detail = `Error ${res.status}`;
    try {
      const data = await res.json();
      if (data?.detail) detail = typeof data.detail === 'string' ? data.detail : JSON.stringify(data.detail);
    } catch { /* no-json */ }

    // Token vencido o inválido: dejamos la sesión en un estado consistente
    // y (si estamos en una página protegida) redirigimos a la landing.
    // No redirigimos desde /auth/login para no entrar en loop cuando
    // las credenciales son incorrectas.
    if (res.status === 401 && !path.startsWith('/api/v1/auth/')) {
      try {
        const prevRole = getSession()?.role;
        clearSession();
        if (typeof window !== 'undefined') {
          const target = prevRole === 'Medico'       ? '/doctor'
                       : prevRole === 'Paciente'     ? '/patient'
                       : prevRole === 'Farmaceutico' ? '/pharmacy/login'
                       : '/';
          // Evita redirigir si ya estamos en la página de login destino.
          if (!window.location.pathname.startsWith(target)) {
            window.location.replace(target);
          }
        }
      } catch { /* noop */ }
    }

    throw new ApiError(res.status, detail);
  }

  if (res.status === 204) return undefined as unknown as T;
  const ct = res.headers.get('content-type') || '';
  if (ct.includes('application/json')) return (await res.json()) as T;
  return (await res.text()) as unknown as T;
}

// ---------------------------------------------------------------------------
// Tipos alineados con backend/src/api_gateway/schemas.py
// ---------------------------------------------------------------------------

export interface LoginRequest { correo: string; contrasena: string; }
export interface TokenResponse { access_token: string; token_type: string; }

export interface AccesoDTO {
  rol: string;        // "paciente" | "farmaceutico" | "doctor"
  wrappedKey: string;
  nonce: string;
}

export interface RecetaCreateDTO {
  /**
   * Ignorado por el backend cuando el emisor es un Médico (se toma del JWT).
   * Sólo se usa cuando un Administrador emite a nombre de otro doctor.
   */
  id_medico?: number;
  id_paciente: number;
  expira_en: string;          // ISO 8601
  capsula_cifrada: string;    // hex
  iv_aes_gcm: string;         // hex
  accesos: AccesoDTO[];
}

export interface RecetaPublicDTO {
  id_receta: number;
  estado: string;
  creada_en: string;
}

export interface UserInfoDTO { nombre_completo: string; }

export interface RecetaDetailDTO extends RecetaPublicDTO {
  expira_en: string;
  medico: UserInfoDTO;
  paciente: UserInfoDTO;
}

export interface RecetaCriptoDTO {
  id_receta: number;
  capsula_cifrada: string;
  iv_aes_gcm: string;
  accesos: AccesoDTO[];
  estado: string;
}

export interface RecetaSellarDTO {
  /**
   * Ignorado por el backend cuando el emisor es un Farmacéutico
   * (se toma del JWT). Se usa sólo en el camino administrativo.
   */
  id_farmaceutico?: number;
  capsula_cifrada: string;
  iv_aes_gcm: string;
  accesos: AccesoDTO[];
}

export interface PacienteCreateDTO {
  nombre: string;
  paterno: string;
  materno?: string | null;
  correo: string;
  contrasena: string;
  id_clinica?: number | null;
  curp: string;
  nacimiento: string;          // YYYY-MM-DD
  sexo: string;
  tel_emergencia: string;
}

export interface MedicoCreateDTO {
  nombre: string;
  paterno: string;
  materno?: string | null;
  correo: string;
  contrasena: string;
  id_clinica: number;
  cedula: string;
  especialidad: string;
  universidad: string;
}

export interface FarmaceuticoCreateDTO {
  nombre: string;
  paterno: string;
  materno?: string | null;
  correo: string;
  contrasena: string;
  id_clinica?: number | null;
  licencia: string;
  turno: string;             // "Matutino" | "Vespertino" | "Nocturno"
}

export interface ClinicaCreateDTO {
  nombre: string;
  clues: string;
  calle: string;
  colonia: string;
  municipio: string;
  estado: string;
  cp: string;
  tipo: string;              // "Centro Medico" | "Hospital"
}

export interface ClinicaPublicDTO {
  id_clinica: number;
  nombre: string;
  clues: string;
  municipio: string;
  estado: string;
  tipo: string;
}

export interface UsuarioPublicDTO {
  id_usuario: number;
  correo: string;
  nombre: string;
  paterno: string;
  rol_nombre: string;
}

// ---------------------------------------------------------------------------
// Endpoints
// ---------------------------------------------------------------------------

export const Api = {
  // ---- Auth ----
  async login(body: LoginRequest): Promise<TokenResponse> {
    return request<TokenResponse>('/api/v1/auth/login', {
      method: 'POST',
      body: JSON.stringify(body),
    });
  },

  /**
   * Login conveniente: autentica, persiste el token en sessionStorage y
   * devuelve la sesión decodificada del JWT.
   */
  async loginAndPersist(body: LoginRequest): Promise<SessionData> {
    const { access_token } = await Api.login(body);
    const payload = decodeJwtPayload(access_token) || {};
    const session: SessionData = {
      id: Number(payload.id),
      correo: String(payload.sub || body.correo),
      role: String(payload.role || ''),
    };
    saveSession(access_token, session);
    return session;
  },

  // ---- Usuarios ----
  async registerPaciente(body: PacienteCreateDTO): Promise<UsuarioPublicDTO> {
    return request<UsuarioPublicDTO>('/api/v1/usuarios/pacientes', {
      method: 'POST',
      body: JSON.stringify(body),
    });
  },

  async registerMedico(body: MedicoCreateDTO): Promise<UsuarioPublicDTO> {
    return request<UsuarioPublicDTO>('/api/v1/usuarios/medicos', {
      method: 'POST',
      body: JSON.stringify(body),
    });
  },

  async registerFarmaceutico(body: FarmaceuticoCreateDTO): Promise<UsuarioPublicDTO> {
    return request<UsuarioPublicDTO>('/api/v1/usuarios/farmaceuticos', {
      method: 'POST',
      body: JSON.stringify(body),
    });
  },

  // ---- Clínicas ----
  async listarClinicas(): Promise<ClinicaPublicDTO[]> {
    return request<ClinicaPublicDTO[]>('/api/v1/clinicas');
  },

  async crearClinica(body: ClinicaCreateDTO): Promise<ClinicaPublicDTO> {
    return request<ClinicaPublicDTO>('/api/v1/clinicas', {
      method: 'POST',
      body: JSON.stringify(body),
    });
  },

  // ---- Recetas ----
  async crearReceta(body: RecetaCreateDTO): Promise<RecetaPublicDTO> {
    return request<RecetaPublicDTO>('/api/v1/recetas', {
      method: 'POST',
      body: JSON.stringify(body),
    });
  },

  async obtenerRecetaInfo(idReceta: number): Promise<RecetaDetailDTO> {
    return request<RecetaDetailDTO>(`/api/v1/recetas/${idReceta}`);
  },

  /**
   * Lista recetas filtradas por paciente y/o médico. El backend exige al
   * menos uno de los dos filtros para evitar listados abiertos.
   */
  async listarRecetas(filters: {
    id_paciente?: number;
    id_medico?: number;
    estado?: 'activa' | 'surtida';
    limit?: number;
  }): Promise<RecetaDetailDTO[]> {
    const params = new URLSearchParams();
    if (filters.id_paciente != null) params.set('id_paciente', String(filters.id_paciente));
    if (filters.id_medico   != null) params.set('id_medico',   String(filters.id_medico));
    if (filters.estado)               params.set('estado',      filters.estado);
    if (filters.limit != null)        params.set('limit',       String(filters.limit));
    return request<RecetaDetailDTO[]>(`/api/v1/recetas?${params.toString()}`);
  },

  async obtenerRecetaCripto(idReceta: number): Promise<RecetaCriptoDTO> {
    return request<RecetaCriptoDTO>(`/api/v1/recetas/${idReceta}/cripto`);
  },

  async sellarReceta(idReceta: number, body: RecetaSellarDTO): Promise<RecetaPublicDTO> {
    return request<RecetaPublicDTO>(`/api/v1/recetas/${idReceta}/sellar`, {
      method: 'PUT',
      body: JSON.stringify(body),
    });
  },

  // ---- Health ----
  async health(): Promise<{ message: string; status: string }> {
    return request('/');
  },
};
