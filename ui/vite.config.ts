import { defineConfig } from "vitest/config";

// The file names are fixed, so that rsim-api embeds each file by its name.
export default defineConfig({
  oxc: { jsx: { runtime: "automatic", importSource: "preact" } },
  build: {
    outDir: "dist",
    emptyOutDir: true,
    assetsInlineLimit: 0,
    modulePreload: { polyfill: false },
    rolldownOptions: {
      output: {
        entryFileNames: "assets/app.js",
        chunkFileNames: "assets/[name].js",
        assetFileNames: "assets/app[extname]",
      },
    },
  },
  server: {
    port: 5173,
    strictPort: true,
    proxy: { "/v1": { target: "http://127.0.0.1:8787", changeOrigin: true } },
  },
  test: {
    include: ["test/**/*.test.ts"],
  },
});
