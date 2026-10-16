import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

const backend = process.env.TESSERA_API ?? "http://127.0.0.1:8000";
// The API, the bootstrap-invitation URL the operator CLI prints (/t/<slug>/bootstrap) and the
// MCP authorization server (/t/<slug>/oauth/* and /t/<slug>/.well-known/*, issue #115).
const proxy = {
  "/api": backend,
  "^/t/[a-z0-9-]+/bootstrap": backend,
  "^/t/[a-z0-9-]+/(oauth|\\.well-known)/": backend,
};

export default defineConfig({
  plugins: [react()],
  build: { chunkSizeWarningLimit: 1200 },
  server: { port: 5173, proxy },
  preview: { port: 5173, proxy },
});
