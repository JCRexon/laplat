import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The dev server proxies the API so the SPA and authd share an origin in
// development (no CORS). Point VITE_API_TARGET at a running authd; default is
// the local dev port.
export default defineConfig(() => {
  const target = process.env.VITE_API_TARGET ?? "http://localhost:8080";
  return {
    plugins: [react()],
    server: {
      port: 5173,
      proxy: {
        "/v1": { target, changeOrigin: true },
      },
    },
  };
});
