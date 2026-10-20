import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

const backend = process.env.TESSERA_API ?? "http://127.0.0.1:8000";
// The API; the bootstrap-invitation URL the operator CLI prints (/t/<slug>/bootstrap); and the OAuth
// authorization server tessera-cli talks to (/t/<slug>/oauth/*, the well-known documents) and the MCP
// authorization server (/t/<slug>/mcp/oauth/*, /t/<slug>/mcp/.well-known/*, issue #115). The CLI's
// server URL is TESSERA_PUBLIC_URL, which in development is this dev server, so the DPoP proofs it
// signs (bound to that URL) match what the proxy forwards.
const proxy = {
  "/api": backend,
  // and the guest claim API (/public/t/<slug>/claim), which the claim page calls without a session.
  "/public/t": backend,
  "^/t/[a-z0-9-]+/(bootstrap|oauth/.*|\\.well-known/.*)": backend,
  "/.well-known": backend,
  // the MCP authorization server, its own issuer at /t/<slug>/mcp (issue #115)
  "^/t/[a-z0-9-]+/mcp/(oauth|\\.well-known)/": backend,
};

export default defineConfig({
  plugins: [react()],
  build: { chunkSizeWarningLimit: 1200 },
  server: { port: 5173, proxy },
  preview: { port: 5173, proxy },
});
