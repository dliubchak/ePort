import { expect, it } from "bun:test";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { writeClaudeAuthFile } from "../../src/auth/claude-file.ts";
import { AuthManager } from "../../src/auth/manager.ts";
import { getClaudeCliCredentialsPath } from "../../src/auth/paths.ts";

it("keeps Claude CLI login metadata through successive proxy refreshes", async () => {
  const home = mkdtempSync(join(tmpdir(), "eport-claude-refresh-"));
  const path = getClaudeCliCredentialsPath(home);
  const metadata = {
    scopes: ["user:profile", "user:inference"],
    subscriptionType: "max",
    rateLimitTier: "default_claude_max_5x",
    clientId: "existing-client",
    refreshTokenExpiresAt: Date.now() + 30 * 86400_000,
    futureLoginField: { preserve: true },
  };
  const postedTokens: string[] = [];
  const auth = new AuthManager(home, {
    claudeOauth: {
      exchangeRefreshToken: async (refreshToken) => {
        postedTokens.push(refreshToken);
        return {
          access_token: `access-${postedTokens.length}`,
          ...(postedTokens.length === 1 ? { refresh_token: "refresh-1" } : {}),
          expires_in: 28800,
        };
      },
    },
  });

  try {
    writeClaudeAuthFile(path, {
      claudeAiOauth: {
        accessToken: "access-0",
        refreshToken: "refresh-0",
        expiresAt: Date.now() + 28800_000,
        ...metadata,
      },
      otherCredential: { preserve: true },
    });
    // Populate the same credential cache the running proxy uses.
    await auth.getClaudeCredentials();
    for (let i = 1; i <= 2; i++) {
      expect(await auth.handleUpstreamError("claude", 401)).toBe("retry");
      const saved = JSON.parse(readFileSync(path, "utf8"));
      expect(saved.claudeAiOauth).toMatchObject({
        ...metadata,
        accessToken: `access-${i}`,
        refreshToken: "refresh-1",
      });
      expect(saved.otherCredential).toEqual({ preserve: true });
      expect(saved.claudeAiOauth.expiresAt).toBeGreaterThan(Date.now());
    }
    expect(postedTokens).toEqual(["refresh-0", "refresh-1"]);
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

it("restores missing scope metadata from the OAuth refresh response", async () => {
  const home = mkdtempSync(join(tmpdir(), "eport-claude-scope-"));
  const path = getClaudeCliCredentialsPath(home);
  const auth = new AuthManager(home, {
    claudeOauth: {
      exchangeRefreshToken: async () => ({
        access_token: "renewed-access",
        refresh_token: "renewed-refresh",
        expires_in: 28800,
        scope: "user:profile user:inference user:mcp_servers",
        refresh_token_expires_in: 2592000,
      }),
    },
  });

  try {
    writeClaudeAuthFile(path, {
      claudeAiOauth: {
        accessToken: "old-access",
        refreshToken: "old-refresh",
        expiresAt: Date.now() - 1,
      },
    });
    await auth.getClaudeCredentials();
    const saved = JSON.parse(readFileSync(path, "utf8"));
    expect(saved.claudeAiOauth.scopes).toEqual([
      "user:profile", "user:inference", "user:mcp_servers",
    ]);
    expect(saved.claudeAiOauth.refreshTokenExpiresAt).toBeGreaterThan(Date.now());
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});
