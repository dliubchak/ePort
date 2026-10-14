import {
  claudeNeedsProactiveRefresh,
  credentialsFromClaudeAuthFile,
  isClaudeAccessTokenExpired,
  isClaudeAccessTokenFresh,
  readClaudeAuthFile,
  tokenResponseToClaudeAuthFile,
  writeClaudeAuthFile,
} from "./claude-file.ts";
import {
  resolveClaudeOAuthDeps,
  runClaudeOAuthLogin,
  type ClaudeOAuthDeps,
} from "./claude-oauth.ts";
import { getAccountAuthPath } from "./accounts-paths.ts";
import { AccountsStore } from "./accounts-store.ts";
import type { AccountsStatusSummary } from "./account-types.ts";
import { getCodexCliAuthPath, getEportCodexAuthPath } from "./paths.ts";
import { getClaudeCliCredentialsPath, getEportClaudeAuthPath } from "./paths.ts";
import {
  credentialsFromAuthFile,
  getFileMtimeMs,
  isAccessTokenExpired,
  isAccessTokenFresh,
  needsProactiveRefresh,
  readCodexAuthFile,
  tokenResponseToAuthFile,
  writeCodexAuthFile,
} from "./codex-file.ts";
import {
  resolveOAuthDeps,
  runCodexOAuthLogin,
  type CodexOAuthDeps,
} from "./codex-oauth.ts";
import { extractAccountId } from "./jwt.ts";
import type {
  AuthStatusSummary,
  ClaudeAuthFile,
  ClaudeCredentials,
  CodexAuthFile,
  CodexCredentials,
  CredentialSource,
  Provider,
  ProviderAuthStatus,
} from "./types.ts";
import {
  CLAUDE_REFRESH_TOKEN_EXPIRED_HINT,
  REFRESH_SAFETY_WINDOW_MS,
  REFRESH_TOKEN_EXPIRED_HINT as EXPIRED_HINT,
} from "./types.ts";
import type { ActiveAccountInfo } from "./account-types.ts";
import {
  readProxyRuntimeState,
  writeProxyRuntimeState,
} from "../runtime/state.ts";

interface ResolvedCodexStore {
  source: CredentialSource;
  path: string;
  auth: CodexAuthFile;
  mtimeMs: number;
}

interface ResolvedClaudeStore {
  source: CredentialSource;
  path: string;
  auth: ClaudeAuthFile;
  mtimeMs: number;
}

export interface AuthManagerDeps {
  oauth?: CodexOAuthDeps;
  claudeOauth?: ClaudeOAuthDeps;
}

export class AuthManager {
  private readonly home: string;
  private readonly oauthDeps: ReturnType<typeof resolveOAuthDeps>;
  private readonly claudeOauthDeps: ReturnType<typeof resolveClaudeOAuthDeps>;
  readonly accounts: AccountsStore;
  private cachedCodex: CodexCredentials | null = null;
  private cachedMtimeMs = 0;
  private cachedClaude: ClaudeCredentials | null = null;
  private cachedClaudeMtimeMs = 0;
  private inflightRefresh: Promise<void> | null = null;
  private inflightClaudeRefresh: Promise<void> | null = null;
  private refreshTimer: ReturnType<typeof setTimeout> | null = null;
  private claudeRefreshTimer: ReturnType<typeof setTimeout> | null = null;
  private refreshFailureHint: string | undefined;
  private claudeRefreshFailureHint: string | undefined;
  private catalog: { invalidate(): void } | null = null;
  private runtimePort: number | null = null;

  constructor(home: string, deps: AuthManagerDeps = {}) {
    this.home = home;
    this.oauthDeps = resolveOAuthDeps(deps.oauth);
    this.claudeOauthDeps = resolveClaudeOAuthDeps(deps.claudeOauth);
    this.accounts = new AccountsStore(home);
  }

  status(): AuthStatusSummary {
    return {
      codex: this.inspectCodex(),
      claude: this.inspectClaude(),
    };
  }

  setCatalog(catalog: { invalidate(): void }): void {
    this.catalog = catalog;
  }

  setRuntimePort(port: number): void {
    this.runtimePort = port;
    this.syncRuntimeActiveAccounts();
  }

  accountsStatus(provider?: Provider): AccountsStatusSummary {
    return this.accounts.status(provider);
  }

  getActiveAccounts(): Partial<Record<Provider, ActiveAccountInfo>> {
    const active: Partial<Record<Provider, ActiveAccountInfo>> = {};
    for (const provider of ["codex", "claude"] as const) {
      if (this.accounts.hasQueue(provider)) {
        const info = this.accounts.getActiveInfo(provider);
        if (info) active[provider] = info;
        continue;
      }

      const status = provider === "codex" ? this.inspectCodex() : this.inspectClaude();
      if (!status.authenticated) continue;
      active[provider] = {
        provider,
        id: status.storePath ?? "default",
        index: 1,
        label: status.source === "cli" ? "cli" : "eport-oauth",
      };
    }
    return active;
  }

  syncRuntimeActiveAccounts(): void {
    if (!this.runtimePort) return;
    const existing = readProxyRuntimeState(this.home);
    writeProxyRuntimeState(this.home, {
      pid: process.pid,
      port: this.runtimePort,
      startedAt: existing?.startedAt ?? Date.now(),
      tunnelMode: existing?.tunnelMode,
      publicBaseUrl: existing?.publicBaseUrl,
      activeAccounts: this.getActiveAccounts(),
    });
  }

  async addAccount(provider: Provider, label?: string, verbose = false): Promise<void> {
    const id = crypto.randomUUID();
    const authPath = getAccountAuthPath(this.home, provider, id);

    if (provider === "codex") {
      const auth = await runCodexOAuthLogin(this.home, {
        verbose,
        deps: {
          fetchFn: this.oauthDeps.fetchFn,
          openBrowser: this.oauthDeps.openBrowser,
          loginWithPkce: this.oauthDeps.loginWithPkce,
        },
        authPath,
      });
      const accountKey =
        auth.tokens.account_id ||
        extractAccountId(auth.tokens.id_token) ||
        extractAccountId(auth.tokens.access_token) ||
        undefined;
      this.accounts.addAccount(
        provider,
        { id, authPath, label, accountKey },
        { makeActive: !this.accounts.hasQueue(provider) },
      );
    } else {
      const auth = await runClaudeOAuthLogin(this.home, {
        verbose,
        deps: {
          fetchFn: this.claudeOauthDeps.fetchFn,
          openBrowser: this.claudeOauthDeps.openBrowser,
          loginWithPkce: this.claudeOauthDeps.loginWithPkce,
        },
        authPath,
      });
      this.accounts.addAccount(
        provider,
        { id, authPath, label },
        { makeActive: !this.accounts.hasQueue(provider) },
      );
    }

    this.invalidateProviderCache(provider);
    this.catalog?.invalidate();
    this.syncRuntimeActiveAccounts();
  }

  switchAccount(provider: Provider, selector: string): ActiveAccountInfo {
    const active = this.accounts.switchActive(provider, selector);
    this.invalidateProviderCache(provider);
    this.catalog?.invalidate();
    this.syncRuntimeActiveAccounts();
    return active;
  }

  reorderAccounts(provider: Provider, indices: number[]): ActiveAccountInfo {
    const active = this.accounts.reorder(provider, indices);
    this.invalidateProviderCache(provider);
    this.catalog?.invalidate();
    this.syncRuntimeActiveAccounts();
    return active;
  }

  async handleUpstreamError(
    provider: Provider,
    status: 401 | 429,
  ): Promise<"retry" | "fail"> {
    if (status === 401) {
      try {
        if (provider === "codex") {
          await this.coalescedRefresh();
        } else {
          await this.coalescedClaudeRefresh();
        }
        return "retry";
      } catch {
        // rotate only when refresh fails
      }
    }

    const reason = status === 429 ? "429" : "401-refresh-failed";
    const rotated = this.accounts.rotateToNext(provider, reason);
    if (!rotated) {
      return "fail";
    }

    this.invalidateProviderCache(provider);
    this.catalog?.invalidate();
    this.syncRuntimeActiveAccounts();
    return "retry";
  }

  async login(provider?: Provider): Promise<void> {
    const targets = resolveLoginTargets(provider);
    for (const target of targets) {
      if (target === "codex") {
        await this.loginCodex();
      } else {
        await this.loginClaude();
      }
    }
  }

  async getCodexCredentials(): Promise<CodexCredentials> {
    const resolved = this.resolveCodexStore();
    if (!resolved) {
      throw new Error("Codex is not authenticated. Run: eport auth login codex");
    }

    const credentials = credentialsFromAuthFile(
      resolved.auth,
      resolved.source,
      resolved.path,
    );
    this.cachedCodex = credentials;
    this.cachedMtimeMs = resolved.mtimeMs;

    if (needsProactiveRefresh(credentials.accessToken) && !isAccessTokenExpired(credentials.accessToken)) {
      this.scheduleBackgroundRefresh();
      return credentials;
    }

    if (isAccessTokenExpired(credentials.accessToken)) {
      await this.coalescedRefresh();
      const refreshed = this.resolveCodexStore();
      if (!refreshed) {
        throw new Error("Codex credentials expired. Run: eport auth login codex");
      }
      const next = credentialsFromAuthFile(
        refreshed.auth,
        refreshed.source,
        refreshed.path,
      );
      this.cachedCodex = next;
      this.cachedMtimeMs = refreshed.mtimeMs;
      return next;
    }

    this.scheduleProactiveTimer(credentials.expiresAt);
    return credentials;
  }

  async getClaudeCredentials(): Promise<ClaudeCredentials> {
    const resolved = this.resolveClaudeStore();
    if (!resolved) {
      throw new Error("Claude is not authenticated. Run: eport auth login claude");
    }

    const credentials = credentialsFromClaudeAuthFile(
      resolved.auth,
      resolved.source,
      resolved.path,
    );
    this.cachedClaude = credentials;
    this.cachedClaudeMtimeMs = resolved.mtimeMs;

    if (
      claudeNeedsProactiveRefresh(resolved.auth) &&
      !isClaudeAccessTokenExpired(resolved.auth)
    ) {
      this.scheduleClaudeBackgroundRefresh();
      return credentials;
    }

    if (isClaudeAccessTokenExpired(resolved.auth)) {
      await this.coalescedClaudeRefresh();
      const refreshed = this.resolveClaudeStore();
      if (!refreshed) {
        throw new Error("Claude credentials expired. Run: eport auth login claude");
      }
      const next = credentialsFromClaudeAuthFile(
        refreshed.auth,
        refreshed.source,
        refreshed.path,
      );
      this.cachedClaude = next;
      this.cachedClaudeMtimeMs = refreshed.mtimeMs;
      return next;
    }

    this.scheduleClaudeProactiveTimer(credentials.expiresAt);
    return credentials;
  }

  private inspectCodex(): ProviderAuthStatus {
    const resolved = this.resolveCodexStore();
    if (!resolved) {
      return {
        provider: "codex",
        authenticated: false,
        source: "none",
        expiresAt: null,
        needsRefresh: false,
        guidance: "Run `eport auth login codex` (or `codex login` to reuse CLI credentials).",
      };
    }

    const expiresAt = credentialsFromAuthFile(
      resolved.auth,
      resolved.source,
      resolved.path,
    ).expiresAt;
    const authenticated = !isAccessTokenExpired(resolved.auth.tokens.access_token);
    const needsRefresh =
      needsProactiveRefresh(resolved.auth.tokens.access_token) || !authenticated;

    return {
      provider: "codex",
      authenticated,
      source: resolved.source,
      expiresAt: expiresAt > 0 ? expiresAt : null,
      needsRefresh,
      storePath: resolved.path,
      guidance: this.refreshFailureHint ?? (needsRefresh ? EXPIRED_HINT : undefined),
    };
  }

  private inspectClaude(): ProviderAuthStatus {
    const resolved = this.resolveClaudeStore();
    if (!resolved) {
      return {
        provider: "claude",
        authenticated: false,
        source: "none",
        expiresAt: null,
        needsRefresh: false,
        guidance:
          "Run `eport auth login claude` (or `claude login` to reuse CLI credentials).",
      };
    }

    const expiresAt = credentialsFromClaudeAuthFile(
      resolved.auth,
      resolved.source,
      resolved.path,
    ).expiresAt;
    const authenticated = !isClaudeAccessTokenExpired(resolved.auth);
    const needsRefresh =
      claudeNeedsProactiveRefresh(resolved.auth) || !authenticated;

    return {
      provider: "claude",
      authenticated,
      source: resolved.source,
      expiresAt: expiresAt > 0 ? expiresAt : null,
      needsRefresh,
      storePath: resolved.path,
      guidance:
        this.claudeRefreshFailureHint ??
        (needsRefresh ? CLAUDE_REFRESH_TOKEN_EXPIRED_HINT : undefined),
    };
  }

  private async loginCodex(): Promise<void> {
    const cliPath = getCodexCliAuthPath(this.home);
    const cliAuth = readCodexAuthFile(cliPath);
    if (cliAuth && isAccessTokenFresh(cliAuth.tokens.access_token)) {
      console.log(`Codex: reusing fresh CLI credentials (${cliPath})`);
      this.invalidateCache();
      this.catalog?.invalidate();
      this.scheduleProactiveTimerFromStore();
      return;
    }

    const eportPath = getEportCodexAuthPath(this.home);
    const eportAuth = readCodexAuthFile(eportPath);
    if (eportAuth && isAccessTokenFresh(eportAuth.tokens.access_token)) {
      console.log(`Codex: reusing fresh ePort OAuth credentials (${eportPath})`);
      this.invalidateCache();
      this.catalog?.invalidate();
      this.scheduleProactiveTimerFromStore();
      return;
    }

    await runCodexOAuthLogin(this.home, {
      deps: {
        fetchFn: this.oauthDeps.fetchFn,
        openBrowser: this.oauthDeps.openBrowser,
        loginWithPkce: this.oauthDeps.loginWithPkce,
      },
    });
    console.log(`Codex: saved ePort OAuth credentials (${eportPath})`);
    this.invalidateCache();
    this.refreshFailureHint = undefined;
    this.catalog?.invalidate();
    this.scheduleProactiveTimerFromStore();
  }

  private async loginClaude(): Promise<void> {
    const cliPath = getClaudeCliCredentialsPath(this.home);
    const cliAuth = readClaudeAuthFile(cliPath);
    if (cliAuth && isClaudeAccessTokenFresh(cliAuth)) {
      console.log(`Claude: reusing fresh CLI credentials (${cliPath})`);
      this.invalidateClaudeCache();
      this.catalog?.invalidate();
      this.scheduleClaudeProactiveTimerFromStore();
      return;
    }

    const eportPath = getEportClaudeAuthPath(this.home);
    const eportAuth = readClaudeAuthFile(eportPath);
    if (eportAuth && isClaudeAccessTokenFresh(eportAuth)) {
      console.log(`Claude: reusing fresh ePort OAuth credentials (${eportPath})`);
      this.invalidateClaudeCache();
      this.catalog?.invalidate();
      this.scheduleClaudeProactiveTimerFromStore();
      return;
    }

    await runClaudeOAuthLogin(this.home, {
      deps: {
        fetchFn: this.claudeOauthDeps.fetchFn,
        openBrowser: this.claudeOauthDeps.openBrowser,
        loginWithPkce: this.claudeOauthDeps.loginWithPkce,
      },
    });
    console.log(`Claude: saved ePort OAuth credentials (${eportPath})`);
    this.invalidateClaudeCache();
    this.claudeRefreshFailureHint = undefined;
    this.catalog?.invalidate();
    this.scheduleClaudeProactiveTimerFromStore();
  }

  private resolveCodexStore(): ResolvedCodexStore | null {
    const queued = this.resolveCodexStoreFromQueue();
    if (queued) return queued;

    const cliPath = getCodexCliAuthPath(this.home);
    const eportPath = getEportCodexAuthPath(this.home);
    const cliAuth = readCodexAuthFile(cliPath);
    const eportAuth = readCodexAuthFile(eportPath);

    const candidates: ResolvedCodexStore[] = [];
    if (cliAuth) {
      candidates.push({
        source: "cli",
        path: cliPath,
        auth: cliAuth,
        mtimeMs: getFileMtimeMs(cliPath),
      });
    }
    if (eportAuth) {
      candidates.push({
        source: "eport-oauth",
        path: eportPath,
        auth: eportAuth,
        mtimeMs: getFileMtimeMs(eportPath),
      });
    }

    const freshCli = candidates.find(
      (entry) =>
        entry.source === "cli" &&
        isAccessTokenFresh(entry.auth.tokens.access_token),
    );
    if (freshCli) return this.withCache(freshCli);

    const freshEport = candidates.find(
      (entry) =>
        entry.source === "eport-oauth" &&
        isAccessTokenFresh(entry.auth.tokens.access_token),
    );
    if (freshEport) return this.withCache(freshEport);

    const refreshableCli = candidates.find(
      (entry) => entry.source === "cli" && entry.auth.tokens.refresh_token,
    );
    if (refreshableCli) return this.withCache(refreshableCli);

    const refreshableEport = candidates.find(
      (entry) => entry.source === "eport-oauth" && entry.auth.tokens.refresh_token,
    );
    if (refreshableEport) return this.withCache(refreshableEport);

    return null;
  }

  private resolveClaudeStore(): ResolvedClaudeStore | null {
    const queued = this.resolveClaudeStoreFromQueue();
    if (queued) return queued;

    const cliPath = getClaudeCliCredentialsPath(this.home);
    const eportPath = getEportClaudeAuthPath(this.home);
    const cliAuth = readClaudeAuthFile(cliPath);
    const eportAuth = readClaudeAuthFile(eportPath);

    const candidates: ResolvedClaudeStore[] = [];
    if (cliAuth) {
      candidates.push({
        source: "cli",
        path: cliPath,
        auth: cliAuth,
        mtimeMs: getFileMtimeMs(cliPath),
      });
    }
    if (eportAuth) {
      candidates.push({
        source: "eport-oauth",
        path: eportPath,
        auth: eportAuth,
        mtimeMs: getFileMtimeMs(eportPath),
      });
    }

    const freshCli = candidates.find(
      (entry) => entry.source === "cli" && isClaudeAccessTokenFresh(entry.auth),
    );
    if (freshCli) return this.withClaudeCache(freshCli);

    const freshEport = candidates.find(
      (entry) =>
        entry.source === "eport-oauth" && isClaudeAccessTokenFresh(entry.auth),
    );
    if (freshEport) return this.withClaudeCache(freshEport);

    const refreshableCli = candidates.find(
      (entry) =>
        entry.source === "cli" && entry.auth.claudeAiOauth.refreshToken.length > 0,
    );
    if (refreshableCli) return this.withClaudeCache(refreshableCli);

    const refreshableEport = candidates.find(
      (entry) =>
        entry.source === "eport-oauth" &&
        entry.auth.claudeAiOauth.refreshToken.length > 0,
    );
    if (refreshableEport) return this.withClaudeCache(refreshableEport);

    return null;
  }

  private withClaudeCache(entry: ResolvedClaudeStore): ResolvedClaudeStore {
    if (
      this.cachedClaude &&
      this.cachedClaude.storePath === entry.path &&
      this.cachedClaudeMtimeMs === entry.mtimeMs
    ) {
      return {
        ...entry,
        auth: this.claudeAuthFileFromCache(entry.auth),
      };
    }
    return entry;
  }

  private claudeAuthFileFromCache(fallback: ClaudeAuthFile): ClaudeAuthFile {
    if (!this.cachedClaude) return fallback;
    return {
      ...fallback,
      claudeAiOauth: {
        ...fallback.claudeAiOauth,
        accessToken: this.cachedClaude.accessToken,
        refreshToken: this.cachedClaude.refreshToken,
        expiresAt: this.cachedClaude.expiresAt,
      },
      last_refresh: fallback.last_refresh ?? new Date().toISOString(),
    };
  }

  private withCache(entry: ResolvedCodexStore): ResolvedCodexStore {
    if (
      this.cachedCodex &&
      this.cachedCodex.storePath === entry.path &&
      this.cachedMtimeMs === entry.mtimeMs
    ) {
      return {
        ...entry,
        auth: this.authFileFromCache(entry.auth),
      };
    }
    return entry;
  }

  private authFileFromCache(fallback: CodexAuthFile): CodexAuthFile {
    if (!this.cachedCodex) return fallback;
    return {
      ...fallback,
      tokens: {
        id_token: fallback.tokens.id_token,
        access_token: this.cachedCodex.accessToken,
        refresh_token: this.cachedCodex.refreshToken,
        account_id: this.cachedCodex.accountId,
      },
      last_refresh: fallback.last_refresh ?? new Date().toISOString(),
    };
  }

  private scheduleBackgroundRefresh(): void {
    void this.coalescedRefresh().catch((error) => {
      this.refreshFailureHint =
        error instanceof Error && (error as Error & { code?: string }).code === "refresh_token_expired"
          ? EXPIRED_HINT
          : String(error);
    });
  }

  private scheduleClaudeBackgroundRefresh(): void {
    void this.coalescedClaudeRefresh().catch((error) => {
      this.claudeRefreshFailureHint =
        error instanceof Error && (error as Error & { code?: string }).code === "refresh_token_expired"
          ? CLAUDE_REFRESH_TOKEN_EXPIRED_HINT
          : String(error);
    });
  }

  private scheduleProactiveTimerFromStore(): void {
    const resolved = this.resolveCodexStore();
    if (!resolved) return;
    const expiresAt = credentialsFromAuthFile(
      resolved.auth,
      resolved.source,
      resolved.path,
    ).expiresAt;
    this.scheduleProactiveTimer(expiresAt);
  }

  private scheduleClaudeProactiveTimerFromStore(): void {
    const resolved = this.resolveClaudeStore();
    if (!resolved) return;
    const expiresAt = credentialsFromClaudeAuthFile(
      resolved.auth,
      resolved.source,
      resolved.path,
    ).expiresAt;
    this.scheduleClaudeProactiveTimer(expiresAt);
  }

  private scheduleClaudeProactiveTimer(expiresAt: number): void {
    if (this.claudeRefreshTimer) {
      clearTimeout(this.claudeRefreshTimer);
      this.claudeRefreshTimer = null;
    }
    if (expiresAt <= 0) return;

    const delay = Math.max(
      0,
      expiresAt - REFRESH_SAFETY_WINDOW_MS - Date.now(),
    );
    const timer = setTimeout(() => {
      this.claudeRefreshTimer = null;
      this.scheduleClaudeBackgroundRefresh();
    }, delay);
    if (typeof timer.unref === "function") timer.unref();
    this.claudeRefreshTimer = timer;
  }

  private scheduleProactiveTimer(expiresAt: number): void {
    if (this.refreshTimer) {
      clearTimeout(this.refreshTimer);
      this.refreshTimer = null;
    }
    if (expiresAt <= 0) return;

    const delay = Math.max(
      0,
      expiresAt - REFRESH_SAFETY_WINDOW_MS - Date.now(),
    );
    const timer = setTimeout(() => {
      this.refreshTimer = null;
      this.scheduleBackgroundRefresh();
    }, delay);
    if (typeof timer.unref === "function") timer.unref();
    this.refreshTimer = timer;
  }

  private coalescedRefresh(): Promise<void> {
    if (this.inflightRefresh) return this.inflightRefresh;
    this.inflightRefresh = this.refreshOnce().finally(() => {
      this.inflightRefresh = null;
    });
    return this.inflightRefresh;
  }

  private coalescedClaudeRefresh(): Promise<void> {
    if (this.inflightClaudeRefresh) return this.inflightClaudeRefresh;
    this.inflightClaudeRefresh = this.refreshClaudeOnce().finally(() => {
      this.inflightClaudeRefresh = null;
    });
    return this.inflightClaudeRefresh;
  }

  private async refreshOnce(): Promise<void> {
    const resolved = this.resolveCodexStore();
    if (!resolved) {
      throw new Error("No Codex credentials to refresh");
    }

    const refreshToken = resolved.auth.tokens.refresh_token;
    if (!refreshToken) {
      throw new Error("Codex credentials have no refresh_token");
    }

    const tokens = await this.oauthDeps.exchangeRefreshToken(
      refreshToken,
      this.oauthDeps.fetchFn,
    );
    const merged = tokenResponseToAuthFile({
      id_token: tokens.id_token ?? resolved.auth.tokens.id_token,
      access_token: tokens.access_token,
      refresh_token: tokens.refresh_token ?? refreshToken,
    });

    writeCodexAuthFile(resolved.path, merged);
    this.cachedCodex = credentialsFromAuthFile(
      merged,
      resolved.source,
      resolved.path,
    );
    this.cachedMtimeMs = getFileMtimeMs(resolved.path);
    this.refreshFailureHint = undefined;
    this.scheduleProactiveTimer(this.cachedCodex.expiresAt);
  }

  private async refreshClaudeOnce(): Promise<void> {
    const resolved = this.resolveClaudeStore();
    if (!resolved) {
      throw new Error("No Claude credentials to refresh");
    }

    const refreshToken = resolved.auth.claudeAiOauth.refreshToken;
    if (!refreshToken) {
      throw new Error("Claude credentials have no refresh_token");
    }

    const tokens = await this.claudeOauthDeps.exchangeRefreshToken(
      refreshToken,
      this.claudeOauthDeps.fetchFn,
    );
    const merged = tokenResponseToClaudeAuthFile(tokens, resolved.auth);

    writeClaudeAuthFile(resolved.path, merged);
    this.cachedClaude = credentialsFromClaudeAuthFile(
      merged,
      resolved.source,
      resolved.path,
    );
    this.cachedClaudeMtimeMs = getFileMtimeMs(resolved.path);
    this.claudeRefreshFailureHint = undefined;
    this.scheduleClaudeProactiveTimer(this.cachedClaude.expiresAt);
  }

  private resolveCodexStoreFromQueue(): ResolvedCodexStore | null {
    const entry = this.accounts.getActiveEntry("codex");
    if (!entry) return null;
    const auth = readCodexAuthFile(entry.authPath);
    if (!auth) return null;
    return this.withCache({
      source: "eport-oauth",
      path: entry.authPath,
      auth,
      mtimeMs: getFileMtimeMs(entry.authPath),
    });
  }

  private resolveClaudeStoreFromQueue(): ResolvedClaudeStore | null {
    const entry = this.accounts.getActiveEntry("claude");
    if (!entry) return null;
    const auth = readClaudeAuthFile(entry.authPath);
    if (!auth) return null;
    return this.withClaudeCache({
      source: "eport-oauth",
      path: entry.authPath,
      auth,
      mtimeMs: getFileMtimeMs(entry.authPath),
    });
  }

  private invalidateProviderCache(provider: Provider): void {
    if (provider === "codex") {
      this.invalidateCache();
      return;
    }
    this.invalidateClaudeCache();
  }

  private invalidateCache(): void {
    this.cachedCodex = null;
    this.cachedMtimeMs = 0;
  }

  private invalidateClaudeCache(): void {
    this.cachedClaude = null;
    this.cachedClaudeMtimeMs = 0;
  }

  /** Test hook: count in-flight refresh operations. */
  get inflightRefreshCount(): number {
    return this.inflightRefresh ? 1 : 0;
  }

  /** Test hook: count in-flight Claude refresh operations. */
  get inflightClaudeRefreshCount(): number {
    return this.inflightClaudeRefresh ? 1 : 0;
  }
}

function resolveLoginTargets(provider?: Provider): Provider[] {
  if (provider === "codex") return ["codex"];
  if (provider === "claude") return ["claude"];
  return ["codex", "claude"];
}

export function formatAuthStatus(
  summary: AuthStatusSummary,
  options: { json?: boolean; verbose?: boolean } = {},
): string {
  if (options.json) {
    return `${JSON.stringify(summary, null, 2)}\n`;
  }

  const lines: string[] = [];
  for (const row of [summary.codex, summary.claude]) {
    lines.push(`${capitalize(row.provider)}:`);
    lines.push(`  source:     ${formatSource(row)}`);
    lines.push(`  status:     ${row.authenticated ? "authenticated" : "not authenticated"}`);
    lines.push(`  expires:    ${formatExpiry(row.expiresAt)}`);
    lines.push(`  refresh:    ${row.needsRefresh ? "needed" : "not needed"}`);
    if (options.verbose && row.storePath) {
      lines.push(`  path:       ${row.storePath}`);
    }
    if (row.guidance) {
      lines.push(`  note:       ${row.guidance}`);
    }
    lines.push("");
  }
  return `${lines.join("\n").trimEnd()}\n`;
}

function capitalize(value: string): string {
  return value.charAt(0).toUpperCase() + value.slice(1);
}

function formatSource(row: ProviderAuthStatus): string {
  if (row.source === "cli") {
    return row.provider === "claude"
      ? "CLI reuse (~/.claude/.credentials.json)"
      : "CLI reuse (~/.codex/auth.json)";
  }
  if (row.source === "eport-oauth") return "ePort OAuth";
  return "none";
}

function formatExpiry(expiresAt: number | null): string {
  if (!expiresAt) return "—";
  return new Date(expiresAt).toISOString();
}

export { REFRESH_TOKEN_EXPIRED_HINT } from "./types.ts";
