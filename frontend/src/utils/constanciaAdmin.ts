/**
 * Render de la "Constancia Criptográfica" para el panel de Administración.
 *
 * El admin NO posee llaves de descifrado, por lo que la Cadena Original, la
 * firma ECDSA del médico y el HMAC de dispensación viven dentro de la cápsula
 * cifrada y no pueden mostrarse aquí. Esta constancia reproduce únicamente los
 * bloques que el directorio expone públicamente (cápsula, nonce, sobres de
 * acceso) más los metadatos de la receta. Es una bitácora de auditoría, no una
 * copia del contenido clínico.
 *
 * Se genera como string HTML con estilos inline (independiente de Tailwind)
 * para inyectarse en el modal del panel admin y poder imprimirse.
 */
import type { RecetaDetailDTO, RecetaCriptoDTO } from './api.ts'

function esc(s: unknown): string {
  return String(s ?? '—')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
}

const CIFRADO = '— Cifrado dentro de la cápsula · requiere llave del titular —'

function bloque(titulo: string, valor: string, cifrado = false): string {
  const color = cifrado ? '#9ca3af' : '#374151'
  const estilo = cifrado ? 'font-style:italic;' : ''
  return `
    <div style="margin-bottom:16px;">
      <p style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.04em;color:#374151;margin:0 0 4px;">${esc(titulo)}</p>
      <p style="width:100%;box-sizing:border-box;background:#f9fafb;border:1px solid #e5e7eb;border-radius:2px;padding:8px 12px;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:10px;line-height:1.6;color:${color};${estilo}word-break:break-word;white-space:pre-wrap;margin:0;">${valor}</p>
    </div>`
}

function estadoLabel(r: RecetaDetailDTO): string {
  if (r.estado === 'surtida') return 'SURTIDA'
  if (r.vencida) return 'VENCIDA'
  return r.estado.toUpperCase()
}

/** HTML completo de la constancia (versión admin / auditoría). */
export function renderConstanciaAdminHTML(
  receta: RecetaDetailDTO,
  cripto: RecetaCriptoDTO,
): string {
  const sobres = (cripto.accesos ?? [])
    .map(
      (a) => `
      <div style="width:100%;box-sizing:border-box;background:#f9fafb;border:1px solid #e5e7eb;border-radius:2px;padding:8px 12px;margin-bottom:8px;">
        <p style="font-size:10px;font-weight:600;text-transform:uppercase;color:#6b7280;margin:0 0 4px;">Rol: ${esc(a.rol)}</p>
        <p style="font-family:ui-monospace,Menlo,Consolas,monospace;font-size:10px;line-height:1.6;color:#374151;word-break:break-word;margin:0;"><span style="color:#9ca3af;">wrappedKey:</span> ${esc(a.wrappedKey)}</p>
        <p style="font-family:ui-monospace,Menlo,Consolas,monospace;font-size:10px;line-height:1.6;color:#374151;word-break:break-word;margin:4px 0 0;"><span style="color:#9ca3af;">ephemeral_pub:</span> ${esc(a.ephemeral_pub_hex)}</p>
      </div>`,
    )
    .join('')

  return `
  <article style="margin:0 auto;max-width:768px;background:#fff;color:#111827;border:1px solid #d1d5db;font-family:system-ui,Arial,sans-serif;">
    <header style="border-bottom:1px solid #d1d5db;padding:16px 24px;display:flex;align-items:flex-start;justify-content:space-between;gap:16px;">
      <div>
        <h1 style="font-size:14px;font-weight:700;text-transform:uppercase;letter-spacing:.03em;color:#1f2937;margin:0;">Constancia Criptográfica de Receta Electrónica</h1>
        <p style="font-size:10px;color:#6b7280;margin:2px 0 0;">Documento técnico-legal · Bitácora de auditoría · Vista Administrador</p>
      </div>
      <span style="font-size:10px;font-family:ui-monospace,Menlo,Consolas,monospace;color:#9ca3af;white-space:nowrap;padding-top:4px;">v1.0</span>
    </header>

    <section style="padding:16px 24px;border-bottom:1px solid #e5e7eb;">
      <h2 style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:#374151;margin:0 0 12px;">Datos Generales</h2>
      <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:12px 24px;">
        <div>
          <p style="font-size:10px;font-weight:600;text-transform:uppercase;color:#6b7280;margin:0;">Folio de Transacción</p>
          <p style="font-size:12px;font-family:ui-monospace,Menlo,Consolas,monospace;color:#111827;word-break:break-all;margin:2px 0 0;">${esc(receta.folio)}</p>
        </div>
        <div>
          <p style="font-size:10px;font-weight:600;text-transform:uppercase;color:#6b7280;margin:0;">Fecha de Emisión</p>
          <p style="font-size:12px;font-family:ui-monospace,Menlo,Consolas,monospace;color:#111827;word-break:break-all;margin:2px 0 0;">${esc(receta.creada_en)}</p>
        </div>
        <div>
          <p style="font-size:10px;font-weight:600;text-transform:uppercase;color:#6b7280;margin:0;">Vigencia</p>
          <p style="font-size:12px;font-family:ui-monospace,Menlo,Consolas,monospace;color:#111827;word-break:break-all;margin:2px 0 0;">${esc(receta.expira_en)}</p>
        </div>
        <div>
          <p style="font-size:10px;font-weight:600;text-transform:uppercase;color:#6b7280;margin:0;">Estado</p>
          <p style="font-size:12px;font-family:ui-monospace,Menlo,Consolas,monospace;color:#111827;margin:2px 0 0;">${esc(estadoLabel(receta))}</p>
        </div>
      </div>
    </section>

    <section style="padding:16px 24px;border-bottom:1px solid #e5e7eb;">
      <h2 style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:#374151;margin:0 0 12px;">Entidades</h2>
      <div style="display:grid;grid-template-columns:repeat(2,1fr);gap:16px;">
        <div style="border:1px solid #e5e7eb;border-radius:2px;padding:12px;background:#f9fafb;">
          <p style="font-size:10px;font-weight:600;text-transform:uppercase;color:#6b7280;margin:0 0 4px;">Emisor (Médico)</p>
          <p style="font-size:12px;color:#111827;margin:0;">${esc(receta.medico?.nombre_completo)}</p>
          <p style="font-size:10px;font-family:ui-monospace,Menlo,Consolas,monospace;color:#6b7280;margin:4px 0 0;">ID: MED-${esc(receta.id_medico)}</p>
        </div>
        <div style="border:1px solid #e5e7eb;border-radius:2px;padding:12px;background:#f9fafb;">
          <p style="font-size:10px;font-weight:600;text-transform:uppercase;color:#6b7280;margin:0 0 4px;">Receptor (Paciente)</p>
          <p style="font-size:12px;color:#111827;margin:0;">${esc(receta.paciente?.nombre_completo)}</p>
          <p style="font-size:10px;font-family:ui-monospace,Menlo,Consolas,monospace;color:#6b7280;margin:4px 0 0;">ID: PAC-${esc(receta.id_paciente)}</p>
        </div>
      </div>
      <p style="font-size:10px;color:#6b7280;margin:12px 0 0;">Farmacéutico destino: ${esc(receta.farmaceutico?.nombre_completo)} (FAR-${esc(receta.id_farmaceutico)})</p>
    </section>

    <section style="padding:16px 24px;">
      <h2 style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:#374151;margin:0 0 12px;">Bloques Criptográficos</h2>
      ${bloque('Cadena Original del Complemento de Receta', CIFRADO, true)}
      ${bloque('Sello Digital del Emisor (Firma ECDSA del Médico)', CIFRADO, true)}
      ${bloque('Sello de Dispensación (HMAC-SHA256)', receta.estado === 'surtida' ? CIFRADO : '— Receta aún no dispensada —', true)}
      ${bloque('Hash de Integridad de la Cápsula (AES-256-GCM)', esc(cripto.capsula_cifrada))}
      ${bloque('Vector de Inicialización (Nonce)', esc(cripto.nonce))}
      <div>
        <p style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.04em;color:#374151;margin:0 0 4px;">Sobres de Acceso (ECDH + AES-KW)</p>
        ${sobres || '<p style="font-size:10px;color:#9ca3af;margin:0;">Sin sobres de acceso.</p>'}
      </div>
    </section>

    <footer style="border-top:1px solid #d1d5db;padding:12px 24px;">
      <p style="font-size:10px;color:#9ca3af;line-height:1.6;margin:0;">
        Constancia generada por el rol Administrador: reproduce únicamente los bloques
        criptográficos públicos (cápsula AES-256-GCM, nonce y sobres ECDH + AES-KW) y los
        metadatos de la transacción. El contenido clínico, la firma ECDSA P-256 del médico y
        el sello HMAC-SHA256 permanecen cifrados y solo son verificables por el titular de la
        llave correspondiente.
      </p>
    </footer>
  </article>`
}
