import { resolve } from "node:path";
import { describe } from "vitest";
import {
  describeBuildOutput,
  describeCrossPackageImports,
  describeWorkspaceDeps,
  getPkgRoot,
} from "../../shared/src/scaffold-helpers.js";

const pkgRoot = getPkgRoot(import.meta.url);
const distDir = resolve(pkgRoot, "dist");

describe("mcp-server", () => {
  describeBuildOutput(distDir, { shebang: true });
  describeCrossPackageImports(["@secret-vault/shared", "@secret-vault/core"]);
  describeWorkspaceDeps(pkgRoot, ["@secret-vault/shared", "@secret-vault/core"]);
});
