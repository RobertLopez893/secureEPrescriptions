/** @type {import('tailwindcss').Config} */
export default {
  content: ['./src/**/*.{astro,html,js,jsx,ts,tsx}'],
  theme: {
    extend: {
      colors: {
        'px-bg':      '#1a1c2c',
        'px-navy':    '#29366f',
        'px-blue':    '#41a6f6',
        'px-red':     '#e8003d',
        'px-yellow':  '#ffcd75',
        'px-green':   '#38b764',
        'px-purple':  '#b13e53',
        'px-white':   '#f4f4f4',
        'px-gray':    '#c0cbdc',
        'px-dark':    '#1a1c2c',

        // Role pill colors (kept for compat)
        'pill-green':   '#38b764',
        'pill-green-d': '#257a43',
        'pill-green-l': '#d4f5e2',
        'pill-red':     '#e8003d',
        'pill-red-d':   '#b0002e',
        'pill-red-l':   '#ffd4de',
        'pill-blue':    '#41a6f6',
        'pill-blue-d':  '#1a6eb0',
        'pill-blue-l':  '#d4ecff',
        'pill-yellow':  '#ffcd75',
        'pill-yellow-l':'#fff5d4',
        'ink':      '#1a1c2c',
        'ink-mid':  '#29366f',
        'ink-light':'#5b6ee1',
        'border':   '#1a1c2c',
        'border-mid':'#29366f',
        'surface':  '#f4f4f4',
      },
      fontFamily: {
        pixel:  ['"Press Start 2P"', 'monospace'],
        vt:     ['"VT323"', 'monospace'],
        body:   ['"VT323"', 'monospace'],
        display:['"Press Start 2P"', 'monospace'],
        mono:   ['"VT323"', 'monospace'],
      },
    },
  },
  plugins: [],
}
