import type { OAuthAdapter } from "../types";
import { traeAdapter } from "./trae";
import { devinDesktopAdapter } from "./devin-desktop";
import { clineAdapter } from "./cline";
import { kilocodeAdapter } from "./kilocode";
import { freebuffAdapter } from "./freebuff";
import { codebuddyCnAdapter, codebuddyIntlAdapter } from "./codebuddy";
import { githubAdapter } from "./github";
import { gheCopilotAdapter } from "./ghe-copilot";
import { kimiCodingAdapter } from "./kimi-coding";
import { museCodeAdapter } from "./muse-code";
import { minimaxCodeAdapter } from "./minimax-code";
import { workbuddyAdapter } from "./workbuddy";
import { claudeAdapter } from "./claude";
import { codexAdapter } from "./codex";
import { xaiOAuthAdapter } from "./xai-oauth";
import { grokCliAdapter } from "./grok-cli";
import { cursorAdapter } from "./cursor";
import { openferenceAdapter } from "./openference";
import { clinepassAdapter } from "./clinepass";

/**
 * Adapter registry — grows every provider task. engine.ts imports this list
 * and registers each at module init (no cycle: adapters import only types.ts).
 */
export const OAUTH_ADAPTERS: OAuthAdapter[] = [
  traeAdapter,
  devinDesktopAdapter,
  clineAdapter,
  kilocodeAdapter,
  freebuffAdapter,
  codebuddyCnAdapter,
  codebuddyIntlAdapter,
  githubAdapter,
  gheCopilotAdapter,
  kimiCodingAdapter,
  museCodeAdapter,
  minimaxCodeAdapter,
  workbuddyAdapter,
  claudeAdapter,
  codexAdapter,
  xaiOAuthAdapter,
  grokCliAdapter,
  cursorAdapter,
  openferenceAdapter,
  clinepassAdapter,
];
