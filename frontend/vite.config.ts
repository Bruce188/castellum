import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// https://vite.dev/config/
//
// Bundle splitting: Cytoscape + cose-bilkent move to a dedicated `cytoscape-*.js`
// chunk so the main entry stays under 350 KiB and clients that don't render the
// topology view (or render it lazily) skip the heavy graph dep on first paint.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    // Same-origin dev: proxy /api to the backend (SERVER_PORT, 8081 in .env) so the
    // app uses a relative API base and needs no CORS — mirrors the packaged topology
    // where the backend serves both the SPA and the API on a single origin.
    proxy: { '/api': 'http://127.0.0.1:8081' },
  },
  build: {
    rollupOptions: {
      output: {
        manualChunks: (id: string) => {
          if (id.includes('node_modules/cytoscape')) return 'cytoscape';
          return undefined;
        },
      },
    },
  },
})
