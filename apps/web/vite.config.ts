import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig(({ mode }) => ({
  base: mode === "production" ? "/vulnfuse/" : "/",
  plugins: [react()],
  build: {
    target: "es2022",
  },
  server: {
    port: 4173,
  },
}));
