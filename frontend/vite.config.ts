import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    headers: {
      "Cross-Origin-Opener-Policy": "same-origin",
      "Cross-Origin-Embedder-Policy": "require-corp",
      "Content-Security-Policy": "script-src 'self' 'unsafe-eval' 'unsafe-inline'; worker-src blob: 'self';",
    },
    // Avoid CORS "Failed to fetch" when fhevmjs fetches gateway keyurl: proxy to Zama Sepolia gateway.
    proxy: {
      "/gateway-proxy": {
        target: "https://gateway.sepolia.zama.ai",
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/gateway-proxy/, ""),
      },
    },
  },
  preview: {
    proxy: {
      "/gateway-proxy": {
        target: "https://gateway.sepolia.zama.ai",
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/gateway-proxy/, ""),
      },
    },
  },
  optimizeDeps: {
    exclude: ["fhevmjs"],
  },
})
