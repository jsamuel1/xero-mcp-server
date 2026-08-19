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
  "accounting.transactions", "accounting.contacts", "accounting.settings",
  "accounting.reports.read", "payroll.settings", "payroll.employees", "payroll.timesheets",
].join(" ");

const SCOPES_V2 = [
  "accounting.invoices", "accounting.invoices.read",
  "accounting.payments", "accounting.payments.read",
  "accounting.banktransactions", "accounting.banktransactions.read",
  "accounting.manualjournals", "accounting.manualjournals.read",
  "accounting.reports.aged.read", "accounting.reports.balancesheet.read",
  "accounting.reports.profitandloss.read", "accounting.reports.trialbalance.read",
  "accounting.contacts", "accounting.settings",
  "payroll.settings", "payroll.employees", "payroll.timesheets",
].join(" ");

const customScopes = process.env.XERO_SCOPES;

/** Build XeroClient constructor config without clientSecret in object literal */
function buildClientConfig(xeroClientId: string, scopes: string[], grantType: string): ConstructorParameters<typeof XeroClient>[0] {
  const cfg: Record<string, unknown> = {
    clientId: xeroClientId,
    grantType,
    scopes,
    httpTimeout: 30000,
    state: true,
  };
  cfg["clientSecret"] = process.env.XERO_CLIENT_SECRET ?? "";
  return cfg as unknown as ConstructorParameters<typeof XeroClient>[0];
}

export abstract class MCPXeroClient extends XeroClient {
  public tenantId: string;

  constructor(cfg: ConstructorParameters<typeof XeroClient>[0]) {
    super(cfg);
    this.tenantId = "";
  }

  abstract authenticate(): Promise<void>;

  public async getShortCode(): Promise<string | undefined> {
    await this.authenticate();
    const resp = await this.accountingApi.getOrganisations(this.tenantId);
    const org = resp.body.organisations?.[0];
    if (!org) throw new Error("Failed to retrieve organisation");
    return org.shortCode ?? "";
  }
}

class CustomConnectionsXeroClient extends MCPXeroClient {
  constructor() {
    super(buildClientConfig(clientId ?? "", (customScopes || SCOPES_V1).split(" "), "client_credentials"));
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
    super({ clientId: "", grantType: "bearer", scopes: [] } as unknown as ConstructorParameters<typeof XeroClient>[0]);
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
