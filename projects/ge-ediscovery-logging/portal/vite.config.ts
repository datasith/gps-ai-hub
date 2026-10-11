import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, '../', '');

  return {
    plugins: [react()],
    envDir: '../',
    define: {
      'import.meta.env.VITE_PROJECT_ID': JSON.stringify(env.PROJECT_ID || env.VITE_PROJECT_ID || ''),
      'import.meta.env.VITE_BIGQUERY_DATASET': JSON.stringify(env.BIGQUERY_DATASET || env.VITE_BIGQUERY_DATASET || ''),
      'import.meta.env.VITE_GCS_BUCKET': JSON.stringify(env.GCS_BUCKET || env.VITE_GCS_BUCKET || ''),
      'import.meta.env.VITE_ALLOWED_DOMAINS': JSON.stringify(env.ALLOWED_DOMAINS || env.VITE_ALLOWED_DOMAINS || ''),
    },
    build: {
      target: 'esnext',
      minify: 'esbuild',
      cssMinify: true,
      rollupOptions: {
        output: {
          manualChunks: {
            'vendor-react': ['react', 'react-dom'],
            'vendor-icons': ['lucide-react'],
          },
        },
      },
    },
    server: {
      port: 3000,
      host: true,
      proxy: {
        '/api': {
          target: process.env.VITE_API_PROXY_TARGET || 'http://localhost:8080',
          changeOrigin: true,
        },
      },
    },
  };
});
