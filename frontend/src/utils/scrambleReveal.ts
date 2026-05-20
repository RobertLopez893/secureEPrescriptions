/**
 * Efecto de "descifrado" scramble/reveal para texto sensible.
 *
 * Cada elemento arranca como ruido verde-matrix con parpadeo y se resuelve
 * con un barrido izquierda→derecha; los elementos se escalonan de arriba a
 * abajo para que lea como un barrido descendente. Al terminar, el texto
 * aterriza limpio recuperando su color original.
 *
 * El CSS se inyecta una sola vez en <head> para que el util sea
 * autocontenido y reutilizable desde cualquier página (incl. contenido
 * inyectado por innerHTML, donde los estilos scoped de Astro no aplican).
 */

const STYLE_ID = 'rx-scramble-styles'
const CSS = `
.rx-scramble.rx-cipher {
  animation: rxCipherFlicker .28s steps(2, end) infinite;
  letter-spacing: .02em;
}
@keyframes rxCipherFlicker {
  0%, 100% { opacity: 1; }
  50%      { opacity: .72; }
}
.rx-scramble.rx-clear {
  animation: rxClearIn .55s ease-out both;
  transition: color .55s ease, text-shadow .55s ease;
}
@keyframes rxClearIn {
  from { filter: brightness(1.6); }
  to   { filter: brightness(1); }
}
`

function ensureStyles(): void {
  if (typeof document === 'undefined') return
  if (document.getElementById(STYLE_ID)) return
  const tag = document.createElement('style')
  tag.id = STYLE_ID
  tag.textContent = CSS
  document.head.appendChild(tag)
}

const NOISE = '01@#%&*/\\<>=+$?¬{}[]·•01'
const rnd = () => NOISE[(Math.random() * NOISE.length) | 0]

/**
 * Velocidades preconfiguradas para el efecto.
 * - slow:   ideal cuando es el efecto protagonista (≈6-9s total).
 * - medium: legible y visible sin acaparar la pantalla (≈3-5s total).
 * - fast:   verificación rápida en farmacia (≈1.5-2.5s total).
 *
 * `tick` es el intervalo en ms entre frames; `divisor` controla cuántos
 * caracteres se revelan por frame (len/divisor). `stagger` controla el
 * retraso entre elementos consecutivos.
 */
type Mode = 'slow' | 'medium' | 'fast'
const PRESETS: Record<Mode, { tick: number; divisor: number; stagger: number; startDelay: number }> = {
  slow:   { tick: 95, divisor: 70, stagger: 240, startDelay: 260 },
  medium: { tick: 70, divisor: 45, stagger: 160, startDelay: 180 },
  fast:   { tick: 45, divisor: 30, stagger: 110, startDelay: 120 },
}

/**
 * Anima los elementos dados (típicamente `.rx-scramble`): el texto actual
 * de cada elemento se toma como el valor "real" a revelar.
 *
 * Por defecto usa el preset "slow"; pasa `{ mode: 'medium' }` o
 * `{ mode: 'fast' }` para acelerar.
 */
export function decryptReveal(
  els: HTMLElement[],
  opts: { mode?: Mode } = {},
): void {
  ensureStyles()
  const cfg = PRESETS[opts.mode ?? 'slow']

  els.forEach((el, idx) => {
    const finalText = el.textContent ?? ''
    const cleanColor = el.style.color
    const len = finalText.length
    if (!len) return

    el.classList.add('rx-cipher')
    el.style.color = 'var(--role-doctor)'
    el.style.textShadow = '0 0 6px rgba(56,183,100,.85)'
    el.textContent = Array.from({ length: len }, (_, i) => (finalText[i] === ' ' ? ' ' : rnd())).join('')

    const startDelay = cfg.startDelay + idx * cfg.stagger
    let revealed = 0
    const speed = Math.max(0.25, len / cfg.divisor)
    window.setTimeout(() => {
      const timer = window.setInterval(() => {
        revealed += speed
        const cut = Math.min(len, Math.floor(revealed))
        let out = finalText.slice(0, cut)
        for (let i = cut; i < len; i++) out += finalText[i] === ' ' ? ' ' : rnd()
        // Parpadeo en el carácter del borde que se está resolviendo.
        if (cut > 0 && cut < len && Math.random() < 0.5) {
          out = out.slice(0, cut - 1) + rnd() + out.slice(cut)
        }
        el.textContent = out
        if (cut >= len) {
          window.clearInterval(timer)
          el.textContent = finalText
          el.classList.remove('rx-cipher')
          el.classList.add('rx-clear')
          el.style.color = cleanColor
          el.style.textShadow = 'none'
        }
      }, cfg.tick)
    }, startDelay)
  })
}
