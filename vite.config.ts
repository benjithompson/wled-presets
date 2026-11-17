import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';

export default defineConfig({
  root: 'web',
  plugins: [react(), tailwindcss()],
  build: { outDir: '../dist/web', emptyOutDir: true },
  server: {
    port: Number(process.env.WEB_PORT) || 5790,
    strictPort: true,
    proxy: { '/api': { target: `http://localhost:${process.env.PORT || 8790}`, changeOrigin: false, ws: true } }
  }
});
