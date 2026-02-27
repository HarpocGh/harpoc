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

describe("core", () => {
  describeBuildOutput(distDir);
  describeCrossPackageImports(["@secret-vault/shared"]);
  describeWorkspaceDeps(pkgRoot, ["@secret-vault/shared"]);
});
