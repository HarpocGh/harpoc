import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    name: "core",
    testTimeout: 30_000,
  },
});
