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
    // Não gera um manifest.json, pois usaremos um nome de arquivo fixo
    manifest: false,
    rollupOptions: {
      // Sobrescreve o ponto de entrada
      input: 'static/js/src/index.jsx',
      output: {
        // Define nomes de arquivos fixos para evitar hashes
        entryFileNames: 'bundle.js',
        chunkFileNames: 'chunks.js',
        assetFileNames: 'assets/[name].[ext]',
      },
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