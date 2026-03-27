import { defineConfig } from 'astro/config';
import tailwind from '@astrojs/tailwind';

// https://astro.build/config
export default defineConfig({
  output: 'static',
  integrations: [
    tailwind({
      // Use the global.css entry point for Tailwind processing
      config: { applyBaseStyles: false },
    }),
  ],
  vite: {
    // Ensure CSS is properly processed in production builds
    css: {
      devSourcemap: true,
    },
  },
});
