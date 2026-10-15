import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

const backend = process.env.TESSERA_API ?? "http://127.0.0.1:8000";
// The API, and the bootstrap-invitation URL the operator CLI prints (/t/<slug>/bootstrap).
// /public carries the SSF push receiver.
const proxy = { "/api": backend, "/public": backend, "^/t/[a-z0-9-]+/bootstrap": backend };

export default defineConfig({
  plugins: [react()],
  build: { chunkSizeWarningLimit: 1200 },
  server: { port: 5173, proxy },
  preview: { port: 5173, proxy },
});
