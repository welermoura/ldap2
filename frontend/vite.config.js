import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  build: {
    // Coloca os arquivos compilados na pasta static/react do Flask
    outDir: '../static/react',
    // Gera um manifest para que o Flask possa encontrar os arquivos corretos
    manifest: true,
    rollupOptions: {
      output: {
        // Evita que os nomes dos arquivos tenham hashes
        // Isso simplifica a inclusão dos arquivos no template do Flask
        entryFileNames: `assets/[name].js`,
        chunkFileNames: `assets/[name].js`,
        assetFileNames: `assets/[name].[ext]`
      }
    }
  }
})