import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
        // The local dev proxy keeps browser requests on the frontend origin.
        // The built dashboard is served directly by FastAPI in the demo.
        configure(proxy) {
          proxy.on('proxyReq', request => request.removeHeader('origin'));
        },
      },
    },
  },
  build: { outDir: 'dist', sourcemap: false },
});
