import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    server: {
      // The design system imports its own stylesheet; Node cannot load a .css file, Vite can.
      deps: { inline: ['@d3cloud/ui'] },
    },
  },
});
