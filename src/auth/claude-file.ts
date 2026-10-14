import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";

import { jwtExpiryMs } from "./jwt.ts";
import { getFileMtimeMs } from "./codex-file.ts";
import type { ClaudeAuthFile, ClaudeCredentials, CredentialSource } from "./types.ts";
import { REFRESH_SAFETY_WINDOW_MS } from "./types.ts";

export function parseClaudeAuthFile(raw: unknown): ClaudeAuthFile | null {
  if (!raw || typeof raw !== "object") return null;
  const data = raw as Record<string, unknown>;
  const oauth = data.claudeAiOauth;
  if (!oauth || typeof oauth !== "object") return null;
  const tokenData = oauth as Record<string, unknown>;
  const accessToken =
    typeof tokenData.accessToken === "string" ? tokenData.accessToken : "";
  const refreshToken =
    typeof tokenData.refreshToken === "string" ? tokenData.refreshToken : "";
  if (!accessToken || !refreshToken) return null;

  const expiresAt =
    typeof tokenData.expiresAt === "number" ? tokenData.expiresAt : 0;

  return {
    ...data,
    claudeAiOauth: {
      ...tokenData,
      accessToken,
      refreshToken,
      expiresAt,
    },
    last_refresh:
      typeof data.last_refresh === "string" ? data.last_refresh : undefined,
  };
}

export function readClaudeAuthFile(path: string): ClaudeAuthFile | null {
  if (!existsSync(path)) return null;
  try {
    const raw = JSON.parse(readFileSync(path, "utf8")) as unknown;
    return parseClaudeAuthFile(raw);
  } catch {
    return null;
  }
}

export function writeClaudeAuthFile(path: string, auth: ClaudeAuthFile): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, `${JSON.stringify(auth, null, 2)}\n`, {
    encoding: "utf8",
    mode: 0o600,
  });
}

export function claudeExpiresAtMs(auth: ClaudeAuthFile): number {
  if (auth.claudeAiOauth.expiresAt > 0) {
    return auth.claudeAiOauth.expiresAt;
  }
  return jwtExpiryMs(auth.claudeAiOauth.accessToken) ?? 0;
}

export function credentialsFromClaudeAuthFile(
  auth: ClaudeAuthFile,
  source: CredentialSource,
  storePath: string,
): ClaudeCredentials {
  return {
    accessToken: auth.claudeAiOauth.accessToken,
    refreshToken: auth.claudeAiOauth.refreshToken,
    expiresAt: claudeExpiresAtMs(auth),
    source,
    storePath,
  };
}

export function isClaudeAccessTokenFresh(
  auth: ClaudeAuthFile,
  now = Date.now(),
): boolean {
  const expiresAt = claudeExpiresAtMs(auth);
  if (expiresAt <= 0) return false;
  return now < expiresAt - REFRESH_SAFETY_WINDOW_MS;
}

export function isClaudeAccessTokenExpired(
  auth: ClaudeAuthFile,
  now = Date.now(),
): boolean {
  const expiresAt = claudeExpiresAtMs(auth);
  if (expiresAt <= 0) return true;
  return now >= expiresAt;
}

export function claudeNeedsProactiveRefresh(
  auth: ClaudeAuthFile,
  now = Date.now(),
): boolean {
  const expiresAt = claudeExpiresAtMs(auth);
  if (expiresAt <= 0) return true;
  return now >= expiresAt - REFRESH_SAFETY_WINDOW_MS;
}

export { getFileMtimeMs };

export function tokenResponseToClaudeAuthFile(data: {
  access_token: string;
  refresh_token?: string;
  expires_in?: number;
  scope?: string;
  refresh_token_expires_in?: number;
}, previous?: ClaudeAuthFile): ClaudeAuthFile {
  const expiresAt =
    typeof data.expires_in === "number"
      ? Date.now() + data.expires_in * 1000
      : 0;
  return {
    ...previous,
    claudeAiOauth: {
      ...previous?.claudeAiOauth,
      accessToken: data.access_token,
      refreshToken: data.refresh_token ?? previous?.claudeAiOauth.refreshToken ?? "",
      expiresAt,
      ...(typeof data.scope === "string"
        ? { scopes: data.scope.split(/\s+/).filter(Boolean) }
        : {}),
      ...(typeof data.refresh_token_expires_in === "number"
        ? { refreshTokenExpiresAt: Date.now() + data.refresh_token_expires_in * 1000 }
        : {}),
    },
    last_refresh: new Date().toISOString(),
  };
}
