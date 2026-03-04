import type { VaultEngine } from "@harpoc/core";
import type { VaultApiToken } from "@harpoc/shared";

export type HarpocEnv = {
  Variables: {
    engine: VaultEngine;
    token: VaultApiToken;
  };
};
