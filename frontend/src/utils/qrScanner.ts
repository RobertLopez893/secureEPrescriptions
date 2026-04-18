// src/utils/qrScanner.ts
// Utilidad de lectura de QR desde la cámara del dispositivo.
// Prefiere BarcodeDetector (nativo en Chromium/Edge/Android) y cae a jsQR
// (decodificador TypeScript puro) cuando el API nativo no existe.
//
// Todo queda en el cliente: la imagen nunca sale del navegador.

import jsQR from 'jsqr'

export interface QrScannerOptions {
  /** <video> donde se renderiza el stream. Obligatorio. */
  video: HTMLVideoElement
  /** Cámara preferida. "environment" (trasera) es mejor para escanear. */
  facingMode?: 'environment' | 'user'
  /** Intervalo de muestreo en ms. Default 150 ≈ 6–7 FPS, suficiente. */
  sampleIntervalMs?: number
}

export type QrScannerStopReason = 'detected' | 'manual' | 'error'

export interface QrScannerHandle {
  /** Promesa que resuelve con el texto del QR leído; rechaza si falla. */
  result: Promise<string>
  /** Detiene la cámara + el muestreo (idempotente). */
  stop: (reason?: QrScannerStopReason) => void
}

/**
 * Arranca la cámara, renderiza el preview en el <video> dado y busca un QR
 * cuadro a cuadro. Devuelve un handle con la promesa resultante + stop().
 */
export function startQrScanner(opts: QrScannerOptions): QrScannerHandle {
  const { video } = opts
  const facingMode      = opts.facingMode      ?? 'environment'
  const sampleIntervalMs = opts.sampleIntervalMs ?? 150

  let stream: MediaStream | null = null
  let detector: any = null
  let ticker: ReturnType<typeof setInterval> | null = null
  let stopped = false
  let settled = false

  // Canvas auxiliar para capturar frames → jsQR.
  const canvas = document.createElement('canvas')
  const ctx    = canvas.getContext('2d', { willReadFrequently: true })

  let resolve!: (text: string) => void
  let reject!: (err: Error)   => void
  const result = new Promise<string>((res, rej) => { resolve = res; reject = rej })

  function finish(kind: 'ok' | 'err', payload: string | Error) {
    if (settled) return
    settled = true
    cleanup()
    if (kind === 'ok') resolve(payload as string)
    else               reject(payload as Error)
  }

  function cleanup() {
    if (ticker) { clearInterval(ticker); ticker = null }
    if (stream) {
      for (const t of stream.getTracks()) try { t.stop() } catch {}
      stream = null
    }
    try { video.pause() } catch {}
    try { (video as any).srcObject = null } catch {}
  }

  function stop(_reason: QrScannerStopReason = 'manual') {
    stopped = true
    if (!settled) {
      settled = true
      cleanup()
      reject(new Error('Escaneo cancelado'))
    } else {
      cleanup()
    }
  }

  async function tick() {
    if (stopped || settled) return
    if (video.readyState < 2 || video.videoWidth === 0) return
    const w = video.videoWidth
    const h = video.videoHeight

    // --- 1) BarcodeDetector nativo ---
    if (detector) {
      try {
        const codes = await detector.detect(video)
        if (codes && codes.length > 0 && codes[0].rawValue) {
          finish('ok', String(codes[0].rawValue))
          return
        }
      } catch { /* ignore and try jsQR below */ }
    }

    // --- 2) Fallback jsQR ---
    if (!ctx) return
    canvas.width  = w
    canvas.height = h
    ctx.drawImage(video, 0, 0, w, h)
    let imageData: ImageData
    try { imageData = ctx.getImageData(0, 0, w, h) } catch { return }
    const code = jsQR(imageData.data, imageData.width, imageData.height, {
      inversionAttempts: 'attemptBoth',
    })
    if (code && code.data) {
      finish('ok', code.data)
    }
  }

  async function start() {
    if (!navigator.mediaDevices?.getUserMedia) {
      finish('err', new Error('Este navegador no soporta acceso a la cámara.'))
      return
    }
    try {
      stream = await navigator.mediaDevices.getUserMedia({
        video: { facingMode },
        audio: false,
      })
    } catch (e: any) {
      const msg = e?.name === 'NotAllowedError'
        ? 'Permiso de cámara denegado. Concede acceso y vuelve a intentar.'
        : e?.name === 'NotFoundError'
        ? 'No se detectó ninguna cámara en este dispositivo.'
        : `No se pudo iniciar la cámara (${e?.message || e?.name || 'desconocido'}).`
      finish('err', new Error(msg))
      return
    }

    ;(video as any).srcObject = stream
    video.setAttribute('playsinline', 'true')
    video.muted = true
    try { await video.play() } catch { /* se reintenta en el primer tick */ }

    // Intentar usar BarcodeDetector si existe y soporta QR.
    try {
      const BD = (window as any).BarcodeDetector
      if (BD) {
        let formats: string[] = ['qr_code']
        if (typeof BD.getSupportedFormats === 'function') {
          const supported = await BD.getSupportedFormats()
          if (Array.isArray(supported) && supported.includes('qr_code')) {
            formats = ['qr_code']
          } else {
            formats = []
          }
        }
        if (formats.length) detector = new BD({ formats })
      }
    } catch { detector = null }

    ticker = setInterval(tick, sampleIntervalMs)
  }

  start()

  return { result, stop }
}
