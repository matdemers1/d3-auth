import react from '@vitejs/plugin-react';
import { defineConfig } from 'vite';

export default defineConfig({
  plugins: [react()],
  base: '/',
  build: {
    outDir: 'dist',
    // The server and the bundle budget both read the manifest.
    manifest: true,
    sourcemap: false,
    assetsInlineLimit: 0,
  },
  server: {
    port: 5173,
    // The console's API and the provider live on the server.
    proxy: { '/oidc': 'http://localhost:3000', '/api': 'http://localhost:3000' },
  },
});
