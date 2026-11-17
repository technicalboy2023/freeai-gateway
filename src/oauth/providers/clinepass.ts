import type { OAuthAdapter } from "../types";
import { clineAdapter } from "./cline";

/** ClinePass is the same WorkOS sign-in flow exposed under its own provider key. */
export const clinepassAdapter: OAuthAdapter = {
  ...clineAdapter,
  prefix: "clinepass",
  instructions:
    "ClinePass — same Cline WorkOS sign-in. Open the URL, sign in, then paste the returned authorization code here.",
};
