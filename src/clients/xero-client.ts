import "dotenv/config";
import { XeroClient } from "xero-node";
import { OAuth2WebXeroClient } from "./oauth2-web-client.js";

const clientId = process.env.XERO_CLIENT_ID;
const bearerToken = process.env.XERO_CLIENT_BEARER_TOKEN;
const redirectUri = process.env.XERO_REDIRECT_URI;

if (!bearerToken && !clientId) {
  throw Error(
    "Environment Variables not set - please check your .env file. " +
    "Set XERO_CLIENT_ID + XERO_CLIENT_SECRET (+ XERO_REDIRECT_URI for free OAuth2 flow), " +
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

  constructor(xeroNodeConfig: Record<string, unknown>) {
    super(xeroNodeConfig as Parameters<typeof XeroClient.prototype.constructor>[0]);
    this.tenantId = "";
  }

  abstract authenticate(): Promise<void>;
}

class CustomConnectionsXeroClient extends MCPXeroClient {
  constructor() {
    const scopes = (customScopes || SCOPES_V1).split(" ");
    const cfg: Record<string, unknown> = {
      clientId: clientId ?? "",
      grantType: "client_credentials",
      scopes,
      httpTimeout: 30000,
      state: true,
    };
    cfg["clientSecret"] = process.env.XERO_CLIENT_SECRET ?? "";
    super(cfg);
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
    if (!tenants || tenants.length === 0) throw new Error("No Xero tenants found.");
    this.tenantId = tenants[0].tenantId;
  }
}

class BearerTokenXeroClient extends MCPXeroClient {
  private readonly token: string;

  constructor(token: string) {
    super({ clientId: "", grantType: "bearer", scopes: [] });
    this.token = token;
  }

  async authenticate(): Promise<void> {
    this.setTokenSet({ access_token: this.token });
    const tenants = await this.updateTenants(false);
    if (!tenants || tenants.length === 0) throw new Error("No Xero tenants found.");
    this.tenantId = tenants[0].tenantId;
  }
}

// Auth mode priority:
// 1. XERO_CLIENT_BEARER_TOKEN  => BearerTokenXeroClient
// 2. XERO_REDIRECT_URI set     => OAuth2WebXeroClient (free Web App PKCE flow)
// 3. XERO_CLIENT_ID + SECRET   => CustomConnectionsXeroClient (paid Custom Connection)
export type XeroMCPClient = MCPXeroClient | OAuth2WebXeroClient;

let xeroClientInstance: XeroMCPClient;

if (bearerToken) {
  xeroClientInstance = new BearerTokenXeroClient(bearerToken);
} else if (redirectUri) {
  if (!clientId) throw Error("XERO_REDIRECT_URI set but XERO_CLIENT_ID is missing.");
  xeroClientInstance = new OAuth2WebXeroClient({ clientId, redirectUri });
} else {
  xeroClientInstance = new CustomConnectionsXeroClient();
}

export const xeroClient = xeroClientInstance;
