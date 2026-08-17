import "dotenv/config";
import { XeroClient } from "xero-node";
import { OAuth2WebXeroClient } from "./oauth2-web-client.js";

const client_id = process.env.XERO_CLIENT_ID;
const client_secret=[REDACTED_PASSWORD]
const bearer_token = process.env.XERO_CLIENT_BEARER_TOKEN;
const redirect_uri = process.env.XERO_REDIRECT_URI;
const grant_type = "client_credentials";

if (!bearer_token && (!client_id || !client_secret)) {
  throw Error(
    "Environment Variables not set - please check your .env file. " +
      "Set XERO_CLIENT_ID + XERO_CLIENT_SECRET (add XERO_REDIRECT_URI for free OAuth2 Web App flow), " +
      "or set XERO_CLIENT_BEARER_TOKEN."
  );
}

const SCOPES_V1 = [
  "accounting.transactions",
  "accounting.contacts",
  "accounting.settings",
  "accounting.reports.read",
  "payroll.settings",
  "payroll.employees",
  "payroll.timesheets",
].join(" ");

const SCOPES_V2 = [
  "accounting.invoices",
  "accounting.invoices.read",
  "accounting.payments",
  "accounting.payments.read",
  "accounting.banktransactions",
  "accounting.banktransactions.read",
  "accounting.manualjournals",
  "accounting.manualjournals.read",
  "accounting.reports.aged.read",
  "accounting.reports.balancesheet.read",
  "accounting.reports.profitandloss.read",
  "accounting.reports.trialbalance.read",
  "accounting.contacts",
  "accounting.settings",
  "payroll.settings",
  "payroll.employees",
  "payroll.timesheets",
].join(" ");

const customScopes = process.env.XERO_SCOPES;

export abstract class MCPXeroClient extends XeroClient {
  public tenantId: string;

  constructor(config: {
    clientId: string;
    clientSecret=[REDACTED_PASSWORD]
    grantType: string;
    scopes: string;
  }) {
    super({
      clientId: config.clientId,
      clientSecret=[REDACTED_PASSWORD]
      grantType: config.grantType,
      scopes: config.scopes ? config.scopes.split(" ") : [],
      httpTimeout: 30000,
      state: true,
    });
    this.tenantId = "";
  }

  abstract authenticate(): Promise<void>;
}

class CustomConnectionsXeroClient extends MCPXeroClient {
  private readonly _clientId: string;
  private readonly _clientSecret=[REDACTED_PASSWORD]

  constructor(config: { clientId: string; clientSecret=[REDACTED_PASSWORD] }) {
    const scopes = customScopes || SCOPES_V1;
    super({
      clientId: config.clientId,
      clientSecret=[REDACTED_PASSWORD]
      grantType: grant_type,
      scopes,
    });
    this._clientId = config.clientId;
    this._clientSecret=[REDACTED_PASSWORD]
  }

  async authenticate(): Promise<void> {
    try {
      await this.getClientCredentialsToken();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      if (msg.includes("invalid_scope") && !customScopes) {
        (this as unknown as { config: { scopes: string[] } }).config.scopes = SCOPES_V2.split(" ");
        await this.getClientCredentialsToken();
      } else {
        throw err;
      }
    }
    const tenants = await this.updateTenants(false);
    if (!tenants || tenants.length === 0) {
      throw new Error("No Xero tenants found after authentication.");
    }
    this.tenantId = tenants[0].tenantId;
  }
}

class BearerTokenXeroClient extends MCPXeroClient {
  private readonly bearerToken: string;

  constructor(config: { bearerToken: string }) {
    super({
      clientId: "",
      clientSecret=[REDACTED_PASSWORD]
      grantType: "bearer",
      scopes: "",
    });
    this.bearerToken = config.bearerToken;
  }

  async authenticate(): Promise<void> {
    this.setTokenSet({ access_token: this.bearerToken });
    const tenants = await this.updateTenants(false);
    if (!tenants || tenants.length === 0) {
      throw new Error("No Xero tenants found with provided bearer token.");
    }
    this.tenantId = tenants[0].tenantId;
  }
}

// Singleton selection:
// 1. XERO_CLIENT_BEARER_TOKEN  \u2192 BearerTokenXeroClient
// 2. XERO_REDIRECT_URI set     \u2192 OAuth2WebXeroClient (free Web App flow)
// 3. XERO_CLIENT_ID + SECRET   \u2192 CustomConnectionsXeroClient (paid Custom Connection)
export type XeroMCPClient = MCPXeroClient | OAuth2WebXeroClient;

let xeroClientInstance: XeroMCPClient;

if (bearer_token) {
  xeroClientInstance = new BearerTokenXeroClient({ bearerToken: bearer_token });
} else if (redirect_uri) {
  if (!client_id || !client_secret) {
    throw Error(
      "XERO_REDIRECT_URI is set but XERO_CLIENT_ID or XERO_CLIENT_SECRET is missing."
    );
  }
  xeroClientInstance = new OAuth2WebXeroClient({
    clientId: client_id,
    clientSecret=[REDACTED_PASSWORD]
    redirectUri: redirect_uri,
  });
} else {
  xeroClientInstance = new CustomConnectionsXeroClient({
    clientId: client_id!,
    clientSecret=[REDACTED_PASSWORD]
  });
}

export const xeroClient = xeroClientInstance;
