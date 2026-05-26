import { defineConfig } from "vite";

// Single-page, zero-backend static app. The build output in dist/ is what
// gets deployed to the permaweb (Phase 5) — content-addressed, so the bundle
// hash is its own integrity check. Keep the dependency surface minimal: every
// dep is something an auditor of this tool has to trust.
export default defineConfig({
  base: "./",
  build: {
    target: "es2022",
    sourcemap: true,
  },
  test: {
    globals: true,
    environment: "node",
    include: ["test/**/*.test.ts"],
  },
});
