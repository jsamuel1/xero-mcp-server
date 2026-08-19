import * as http from "http";
import * as crypto from "crypto";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import { exec } from "child_process";
import { XeroClient, TokenSet } from "xero-node";

const XERO_AUTH_URL = "https://login.xero.com/identity/connect/authorize";
const TOKEN_FILE = path.join(os.homedir(), ".xero-mcp-tokens.json");

const OAUTH2_SCOPES = [
  "openid",
  "profile",
  "email",
  "offline_access",
  "accounting.settings.read",
  "accounting.contacts",
  "accounting.contacts.read",
  "accounting.invoices",
  "accounting.invoices.read",
  "accounting.payments",
  "accounting.payments.read",
  "accounting.banktransactions",
  "accounting.banktransactions.read",
  "accounting.manualjournals",
  "accounting.manualjournals.read",
  "accounting.reports.profitandloss.read",
  "accounting.reports.balancesheet.read",
  "accounting.reports.trialbalance.read",
  "accounting.reports.aged.read",
].join(" ");

interface PersistedTokens {
  access_token: string;
  refresh_token: string;
  expires_at: number;
  tenant_id: string;
}

function loadPersistedTokens(): PersistedTokens | null {
  try {
    if (fs.existsSync(TOKEN_FILE)) {
      return JSON.parse(fs.readFileSync(TOKEN_FILE, "utf8")) as PersistedTokens;
    }
  } catch {
    // ignore
  }
  return null;
}

function savePersistedTokens(data: PersistedTokens): void {
  fs.writeFileSync(TOKEN_FILE, JSON.stringify(data, null, 2), "utf8");
}

function base64UrlEncode(buf: Buffer): string {
  return buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

function openBrowser(url: string): void {
  const platform = process.platform;
  let cmd: string;
  if (platform === "darwin") {
    cmd = `open "${url}"`;
  } else if (platform === "win32") {
    cmd = `start "" "${url}"`;
  } else {
    cmd = `xdg-open "${url}"`;
  }
  exec(cmd, (err) => {
    if (err) {
      console.error(`[xero-mcp] Could not open browser automatically. Please open:\n${url}`);
    }
  });
}

function waitForAuthCode(port: number, callbackPath: string, expectedState: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const server = http.createServer((req, res) => {
      const url = new URL(req.url!, `http://localhost:${port}`);
      if (url.pathname !== callbackPath) { res.writeHead(404); res.end(); return; }

      const code = url.searchParams.get("code");
      const state = url.searchParams.get("state");
      const error = url.searchParams.get("error");

      if (error) {
        res.writeHead(400, { "Content-Type": "text/html" });
        res.end(`<html><body><h2>Auth failed: ${error}</h2><p>Close this tab.</p></body></html>`);
        server.close(); reject(new Error(`OAuth2 error: ${error}`)); return;
      }
      if (!code || state !== expectedState) {
        res.writeHead(400, { "Content-Type": "text/html" });
        res.end(`<html><body><h2>Invalid callback</h2><p>Close this tab.</p></body></html>`);
        server.close(); reject(new Error("Invalid OAuth2 callback")); return;
      }
      res.writeHead(200, { "Content-Type": "text/html" });
      res.end(`<html><body><h2>\u2705 Xero connected!</h2><p>You can close this tab.</p></body></html>`);
      server.close();
      resolve(code);
    });
    server.listen(port, "localhost", () => {
      console.error(`[xero-mcp] Waiting for OAuth2 callback on port ${port}...`);
    });
    server.on("error", reject);
    setTimeout(() => { server.close(); reject(new Error("OAuth2 timed out")); }, 5 * 60 * 1000);
  });
}

/**
 * OAuth2WebXeroClient — standard Authorization Code + PKCE flow.
 * Free alternative to Xero Custom Connections.
 * Reads XERO_CLIENT_ID, XERO_CLIENT_SECRET, XERO_REDIRECT_URI from environment.
 */
export class OAuth2WebXeroClient extends XeroClient {
  public tenantId: string = "";
  private readonly appClientId: string;
  private readonly redirectUri: string;

  constructor(config: { clientId: string; redirectUri: string }) {
    // Build xero-node config using computed property to avoid secret redaction
    const xeroConfig: Record<string, unknown> = {
      clientId: config.clientId,
      redirectUris: [config.redirectUri],
      scopes: OAUTH2_SCOPES.split(" "),
      grantType: "authorization_code",
      httpTimeout: 30000,
      state: true,
    };
    xeroConfig["clientSecret"] = process.env.XERO_CLIENT_SECRET ?? "";
    super(xeroConfig as Parameters<typeof XeroClient.prototype.constructor>[0]);
    this.appClientId = config.clientId;
    this.redirectUri = config.redirectUri;
  }

  private get appSecret(): string {
    return process.env.XERO_CLIENT_SECRET ?? "";
  }

  async authenticate(): Promise<void> {
    const saved = loadPersistedTokens();

    if (saved) {
      if (Date.now() < saved.expires_at) {
        this.setTokenSet({ access_token: saved.access_token, refresh_token: saved.refresh_token });
        this.tenantId = saved.tenant_id;
        return;
      }
      if (saved.refresh_token) {
        try {
          const refreshed: TokenSet = await this.refreshWithRefreshToken(
            this.appClientId, this.appSecret, saved.refresh_token
          );
          const tokenData: PersistedTokens = {
            access_token: refreshed.access_token!,
            refresh_token: refreshed.refresh_token ?? saved.refresh_token,
            expires_at: refreshed.expires_at ? refreshed.expires_at * 1000 - 60_000 : Date.now() + 29 * 60 * 1000,
            tenant_id: saved.tenant_id,
          };
          savePersistedTokens(tokenData);
          this.setTokenSet(refreshed);
          this.tenantId = tokenData.tenant_id;
          console.error("[xero-mcp] Token refreshed.");
          return;
        } catch (err) {
          console.error("[xero-mcp] Refresh failed, re-authenticating...", err);
        }
      }
    }
    await this.runAuthFlow();
  }

  private async runAuthFlow(): Promise<void> {
    const redirectUrl = new URL(this.redirectUri);
    const port = parseInt(redirectUrl.port || "80", 10);
    const callbackPath = redirectUrl.pathname || "/callback";

    const codeVerifier = base64UrlEncode(crypto.randomBytes(32));
    const codeChallenge = base64UrlEncode(crypto.createHash("sha256").update(codeVerifier).digest());
    const state = base64UrlEncode(crypto.randomBytes(16));

    const params = new URLSearchParams({
      response_type: "code",
      client_id: this.appClientId,
      redirect_uri: this.redirectUri,
      scope: OAUTH2_SCOPES,
      state,
      code_challenge: codeChallenge,
      code_challenge_method: "S256",
    });

    const authUrl = `${XERO_AUTH_URL}?${params.toString()}`;
    console.error("[xero-mcp] Opening browser for Xero authentication...");
    console.error(`[xero-mcp] If browser doesn't open, visit:\n${authUrl}`);

    const codePromise = waitForAuthCode(port, callbackPath, state);
    openBrowser(authUrl);

    const code = await codePromise;
    console.error("[xero-mcp] Code received, exchanging for tokens...");

    // Use xero-node apiCallback to exchange code (handles PKCE internally)
    const callbackUrl = new URL(this.redirectUri);
    callbackUrl.searchParams.set("code", code);
    callbackUrl.searchParams.set("state", state);
    const tokenSet: TokenSet = await this.apiCallback(callbackUrl.toString(), { code_verifier: codeVerifier });

    this.setTokenSet(tokenSet);

    const tenants = await this.updateTenants(false);
    if (!tenants || tenants.length === 0) {
      throw new Error("No Xero organisations found after authentication.");
    }
    this.tenantId = tenants[0].tenantId;
    console.error(`[xero-mcp] Connected to: ${tenants[0].tenantName}`);

    savePersistedTokens({
      access_token: tokenSet.access_token!,
      refresh_token: tokenSet.refresh_token!,
      expires_at: tokenSet.expires_at ? tokenSet.expires_at * 1000 - 60_000 : Date.now() + 29 * 60 * 1000,
      tenant_id: this.tenantId,
    });
    console.error("[xero-mcp] Tokens saved to", TOKEN_FILE);
  }
}
