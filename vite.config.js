import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  build: {
    // O diretório de saída será 'static/js/dist', como antes
    outDir: 'static/js/dist',
    // Limpa o diretório de saída antes de cada build
    emptyOutDir: true,
    // Gera um manifest.json para que o Flask possa encontrar os arquivos corretos
    manifest: true,
    rollupOptions: {
      // Sobrescreve o ponto de entrada, pois não estamos usando um index.html
      input: 'static/js/src/index.jsx',
    },
  },
  server: {
    // Configura um proxy para o nosso backend Flask
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:5000',
        changeOrigin: true,
      },
    },
  },
})