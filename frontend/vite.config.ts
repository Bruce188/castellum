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
