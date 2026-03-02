import { CREATE_REVOKED_TOKENS, CREATE_REVOKED_TOKENS_INDEXES } from "../schema.js";

export const migration002 = {
  version: 2,
  up: [CREATE_REVOKED_TOKENS, CREATE_REVOKED_TOKENS_INDEXES].join("\n"),
};
