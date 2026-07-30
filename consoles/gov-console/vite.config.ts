import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 8404,
    proxy: {
      '/api/analytics': { target: 'http://localhost:8401', rewrite: (p) => p.replace(/^\/api\/analytics/, '') },
      '/api/jrb': { target: 'http://localhost:8402', rewrite: (p) => p.replace(/^\/api\/jrb/, '') },
      '/api/ombud': { target: 'http://localhost:8403', rewrite: (p) => p.replace(/^\/api\/ombud/, '') },
      '/api/gateway': { target: 'http://localhost:8400', rewrite: (p) => p.replace(/^\/api\/gateway/, '') },
    },
  },
})
