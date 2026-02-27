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

describe("rest-api", () => {
  describeBuildOutput(distDir);
  describeCrossPackageImports(["@secret-vault/shared", "@secret-vault/core"]);
  describeWorkspaceDeps(pkgRoot, ["@secret-vault/shared", "@secret-vault/core"]);
});
