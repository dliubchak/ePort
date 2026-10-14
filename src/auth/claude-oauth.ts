import { createHash, randomBytes } from "node:crypto";
import * as readline from "node:readline/promises";
import { stdin as input, stdout as output } from "node:process";

import {
  readClaudeAuthFile,
  tokenResponseToClaudeAuthFile,
  writeClaudeAuthFile,
} from "./claude-file.ts";
import { getEportClaudeAuthPath } from "./paths.ts";
import type { ClaudeAuthFile } from "./types.ts";

const CLAUDE_CLIENT_ID = "9d1c250a-e61b-44d9-88ed-5944d1962f5e";
const CLAUDE_REDIRECT_URI = "https://console.anthropic.com/oauth/code/callback";
const CLAUDE_TOKEN_URL = "https://console.anthropic.com/v1/oauth/token";

export interface ClaudeOAuthTokenResponse {
  access_token: string;
  refresh_token?: string;
  expires_in?: number;
  scope?: string;
  refresh_token_expires_in?: number;
}

export interface ClaudeOAuthDeps {
  fetchFn?: typeof fetch;
  openBrowser?: (url: string) => Promise<void>;
  loginWithPkce?: (options: {
    verbose?: boolean;
    fetchFn: typeof fetch;
    openBrowser: (url: string) => Promise<void>;
  }) => Promise<ClaudeAuthFile>;
  exchangeRefreshToken?: (
    refreshToken: string,
    fetchFn: typeof fetch,
  ) => Promise<ClaudeOAuthTokenResponse>;
}

function defaultOpenBrowser(url: string): Promise<void> {
  const platform = process.platform;
  const command =
    platform === "darwin"
      ? ["open", url]
      : platform === "win32"
        ? ["cmd", "/c", "start", "", url]
        : ["xdg-open", url];
  return Bun.spawn({ cmd: command, stdout: "ignore", stderr: "ignore" })
    .exited.then(() => undefined);
}

function generatePkce(): { codeVerifier: string; codeChallenge: string } {
  const codeVerifier = randomBytes(32).toString("base64url");
  const codeChallenge = createHash("sha256")
    .update(codeVerifier)
    .digest("base64url");
  return { codeVerifier, codeChallenge };
}

function buildAuthorizeUrl(codeChallenge: string, state: string): string {
  const params: Record<string, string> = {
    code: "true",
    client_id: CLAUDE_CLIENT_ID,
    response_type: "code",
    redirect_uri: CLAUDE_REDIRECT_URI,
    scope: "org:create_api_key user:profile user:inference",
    code_challenge: codeChallenge,
    code_challenge_method: "S256",
    state,
  };
  const qs = Object.entries(params)
    .map(([key, value]) => `${encodeURIComponent(key)}=${encodeURIComponent(value)}`)
    .join("&");
  return `https://claude.ai/oauth/authorize?${qs}`;
}

export async function exchangeClaudeRefreshToken(
  refreshToken: string,
  fetchFn: typeof fetch = fetch,
): Promise<ClaudeOAuthTokenResponse> {
  const response = await fetchFn(CLAUDE_TOKEN_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      grant_type: "refresh_token",
      client_id: CLAUDE_CLIENT_ID,
      refresh_token: refreshToken,
    }),
  });
  if (!response.ok) {
    const text = await response.text().catch(() => "");
    const error = new Error(`Claude token refresh failed: ${response.status} ${text}`);
    if (text.includes("invalid_grant") || text.includes("refresh_token")) {
      (error as Error & { code?: string }).code = "refresh_token_expired";
    }
    throw error;
  }
  return (await response.json()) as ClaudeOAuthTokenResponse;
}

async function exchangeAuthorizationCode(
  codeInput: string,
  codeVerifier: string,
  fetchFn: typeof fetch,
): Promise<ClaudeOAuthTokenResponse> {
  const parts = codeInput.trim().split("#");
  const code = parts[0] ?? "";
  const state = parts[1] ?? codeVerifier;
  const response = await fetchFn(CLAUDE_TOKEN_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      code,
      state,
      grant_type: "authorization_code",
      client_id: CLAUDE_CLIENT_ID,
      redirect_uri: CLAUDE_REDIRECT_URI,
      code_verifier: codeVerifier,
    }),
  });
  if (!response.ok) {
    const text = await response.text().catch(() => "");
    throw new Error(`Claude OAuth token exchange failed: ${response.status} ${text}`);
  }
  return (await response.json()) as ClaudeOAuthTokenResponse;
}

async function defaultLoginWithPkce(options: {
  verbose?: boolean;
  fetchFn: typeof fetch;
  openBrowser: (url: string) => Promise<void>;
}): Promise<ClaudeAuthFile> {
  const { codeVerifier, codeChallenge } = generatePkce();
  const authUrl = buildAuthorizeUrl(codeChallenge, codeVerifier);

  if (options.verbose) {
    console.log(`Open in browser: ${authUrl}`);
  } else {
    console.log("Opening browser for Claude login...");
  }
  await options.openBrowser(authUrl).catch(() => {
    console.log(`Open this URL in your browser:\n${authUrl}`);
  });

  console.log(
    "After authorizing, paste the authorization code (CODE or CODE#STATE):",
  );
  const rl = readline.createInterface({ input, output });
  try {
    const codeInput = (await rl.question("> ")).trim();
    if (!codeInput) {
      throw new Error("No authorization code provided");
    }
    const tokens = await exchangeAuthorizationCode(
      codeInput,
      codeVerifier,
      options.fetchFn,
    );
    return tokenResponseToClaudeAuthFile(tokens);
  } finally {
    rl.close();
  }
}

export function readTestClaudeOAuthFixture(home: string): ClaudeAuthFile | null {
  const fixturePath = process.env.EPORT_TEST_CLAUDE_OAUTH_FIXTURE;
  if (!fixturePath) return null;
  return readClaudeAuthFile(fixturePath);
}

export async function runClaudeOAuthLogin(
  home: string,
  options: { verbose?: boolean; deps?: ClaudeOAuthDeps; authPath?: string } = {},
): Promise<ClaudeAuthFile> {
  const targetPath = options.authPath ?? getEportClaudeAuthPath(home);
  const fixture = readTestClaudeOAuthFixture(home);
  if (fixture) {
    writeClaudeAuthFile(targetPath, fixture);
    return fixture;
  }

  const fetchFn = options.deps?.fetchFn ?? fetch;
  const openBrowser = options.deps?.openBrowser ?? defaultOpenBrowser;
  const loginWithPkce =
    options.deps?.loginWithPkce ??
    ((loginOptions) => defaultLoginWithPkce(loginOptions));

  const authFile = await loginWithPkce({ verbose: options.verbose, fetchFn, openBrowser });
  writeClaudeAuthFile(targetPath, authFile);
  return authFile;
}

export function resolveClaudeOAuthDeps(deps?: ClaudeOAuthDeps): Required<
  Pick<ClaudeOAuthDeps, "fetchFn" | "openBrowser" | "loginWithPkce" | "exchangeRefreshToken">
> {
  const fetchFn = deps?.fetchFn ?? fetch;
  const openBrowser = deps?.openBrowser ?? defaultOpenBrowser;
  return {
    fetchFn,
    openBrowser,
    loginWithPkce:
      deps?.loginWithPkce ??
      ((options) => defaultLoginWithPkce(options)),
    exchangeRefreshToken:
      deps?.exchangeRefreshToken ??
      ((refreshToken, fn) => exchangeClaudeRefreshToken(refreshToken, fn)),
  };
}
