import { assert } from "@/wab/shared/common";
import { getPublicUrl } from "@/wab/shared/urls";
import { loadSecrets } from "@/wab/server/secrets";
import memoizeOne from "memoize-one";

export interface OidcClaimMappings {
  email?: string;
  firstName?: string;
  lastName?: string;
  avatarUrl?: string;
  emailVerified?: string;
}

export interface OidcConfig {
  issuer?: string;
  authorizationURL: string;
  tokenURL: string;
  userInfoURL: string;
  clientID: string;
  clientSecret: string;
  callbackURL: string;
  scope: string;
  buttonLabel: string;
  disableOtherAuth: boolean;
  adminEmailsBypass: string[];
  claimMappings: OidcClaimMappings;
  /**
   * Optional Kratos admin URL for on-site Ory deployments. When set, the OIDC
   * callback will fetch the full Kratos identity (including traits such as
   * given_name/family_name) using the `identity_id` claim from the userinfo
   * response and merge it into the profile before applying claimMappings.
   */
  kratosAdminUrl?: string;
}

export interface Config {
  host: string;
  production: boolean;
  databaseUri: string;
  adminEmails: string[];
  sentryDSN?: string;
  sessionSecret: string;
  mailFrom: string;
  mailUserOps: string;
  mailBcc?: string;
  port?: number;
  terminationGracePeriodMs: number;
  keepAliveTimeoutMs: number;
  genericWorkerPoolSize: number;
  loaderWorkerPoolSize: number;
  oidc?: OidcConfig;
}

export const DEFAULT_DATABASE_URI =
  "postgresql://wab@localhost/" + (process.env.WAB_DBNAME || "wab");

const DEFAULT_CONFIG: Config = {
  host: getPublicUrl(),
  databaseUri: DEFAULT_DATABASE_URI,
  sessionSecret: "x",
  mailFrom: "Plasmic <team@example.com>",
  mailUserOps: "ops@example.com",
  production: process.env.NODE_ENV === "production",
  adminEmails:
    process.env.NODE_ENV !== "production" ? ["admin@admin.example.com"] : [],
  terminationGracePeriodMs: 5500,
  keepAliveTimeoutMs: 60000,
  genericWorkerPoolSize: 1,
  loaderWorkerPoolSize: 1,
};

export const loadConfig = memoizeOne((): Config => {
  const config = parseConfigFromEnv();

  // Validity checks on config
  if (config.production) {
    assert(process.env["SESSION_SECRET"], "Production missing Session Secret");
    assert(process.env["DATABASE_URI"], "Production missing DB Uri");
    assert(process.env["HOST"], "Production missing Host");
  }

  return config;
});

function parseConfigFromEnv(): Config {
  const config = Object.assign({}, DEFAULT_CONFIG);
  const mailConfig = process.env["MAIL_CONFIG"]
    ? JSON.parse(process.env["MAIL_CONFIG"])
    : undefined;
  const rawTerminationGracePeriodMs =
    process.env["TERMINATION_GRACE_PERIOD_MS"];
  const terminationGracePeriodMs =
    rawTerminationGracePeriodMs != null
      ? parseInt(rawTerminationGracePeriodMs, 10)
      : undefined;
  const rawKeepAliveTimeoutMs = process.env["SERVER_KEEP_ALIVE_TIMEOUT"];
  const keepAliveTimeoutMs =
    rawKeepAliveTimeoutMs != null
      ? parseInt(rawKeepAliveTimeoutMs, 10)
      : undefined;

  const envConfig = {
    host: process.env["HOST"],
    databaseUri: process.env["DATABASE_URI"],
    sentryDSN: process.env["SENTRY_DSN"],
    sessionSecret: process.env["SESSION_SECRET"],
    mailFrom: mailConfig?.mailFrom,
    mailUserOps: mailConfig?.mailUserOps,
    mailBcc: mailConfig?.mailBcc,
    adminEmails: process.env["ADMIN_EMAILS"]
      ? (JSON.parse(process.env["ADMIN_EMAILS"]) as string[]).map((email) =>
          email.toLowerCase()
        )
      : undefined,
    terminationGracePeriodMs: terminationGracePeriodMs,
    keepAliveTimeoutMs: keepAliveTimeoutMs,
    genericWorkerPoolSize: process.env["GENERIC_WORKER_POOL_SIZE"]
      ? parseInt(process.env["GENERIC_WORKER_POOL_SIZE"], 10)
      : undefined,
    loaderWorkerPoolSize: process.env["LOADER_WORKER_POOL_SIZE"]
      ? parseInt(process.env["LOADER_WORKER_POOL_SIZE"], 10)
      : undefined,
  };

  Object.entries(envConfig).forEach(([key, value]) => {
    if (value == null) {
      return;
    }
    config[key] = value;
  });

  config.oidc = parseOidcConfigFromEnv(config);

  return config;
}

function getOidcConfigFromSecrets(): Partial<OidcConfig> | undefined {
  const secrets = loadSecrets();
  const s = secrets.oidc;
  if (!s) {
    return undefined;
  }
  return {
    issuer: s.issuer,
    authorizationURL: s.authorizationUrl,
    tokenURL: s.tokenUrl,
    userInfoURL: s.userInfoUrl,
    clientID: s.clientId,
    clientSecret: s.clientSecret,
    callbackURL: s.callbackUrl,
    scope: s.scope,
    buttonLabel: s.buttonLabel,
    disableOtherAuth: s.disableOtherAuth,
    adminEmailsBypass: s.adminEmailsBypass,
    claimMappings: s.claimMappings,
    kratosAdminUrl: s.kratosAdminUrl,
  };
}

const DEFAULT_OIDC_CLAIM_MAPPINGS: OidcClaimMappings = {
  email: "email",
  firstName: "traits.given_name",
  lastName: "traits.family_name",
  avatarUrl: "traits.picture",
  emailVerified: "email_verified",
};

function parseOidcConfigFromEnv(config: Config): OidcConfig | undefined {
  const secrets = getOidcConfigFromSecrets();

  const authorizationURL =
    process.env["OIDC_AUTHORIZATION_URL"] ?? secrets?.authorizationURL;
  const tokenURL = process.env["OIDC_TOKEN_URL"] ?? secrets?.tokenURL;
  const userInfoURL = process.env["OIDC_USER_INFO_URL"] ?? secrets?.userInfoURL;
  const clientID = process.env["OIDC_CLIENT_ID"] ?? secrets?.clientID;
  const clientSecret = process.env["OIDC_CLIENT_SECRET"] ?? secrets?.clientSecret;

  if (
    !authorizationURL ||
    !tokenURL ||
    !userInfoURL ||
    !clientID ||
    !clientSecret
  ) {
    return undefined;
  }

  const rawAdminEmailsBypass =
    process.env["OIDC_ADMIN_EMAILS_BYPASS"] ??
    (secrets?.adminEmailsBypass
      ? JSON.stringify(secrets.adminEmailsBypass)
      : undefined);

  const adminEmailsBypass = rawAdminEmailsBypass
    ? (JSON.parse(rawAdminEmailsBypass) as string[]).map((email) =>
        email.toLowerCase()
      )
    : config.adminEmails;

  const envClaimMappings = process.env["OIDC_CLAIM_MAPPINGS"]
    ? JSON.parse(process.env["OIDC_CLAIM_MAPPINGS"])
    : undefined;
  const secretsClaimMappings = secrets?.claimMappings ?? {};
  const claimMappings: OidcClaimMappings = {
    ...DEFAULT_OIDC_CLAIM_MAPPINGS,
    ...secretsClaimMappings,
    ...envClaimMappings,
    email:
      process.env["OIDC_CLAIM_EMAIL"] ??
      envClaimMappings?.email ??
      secretsClaimMappings.email ??
      DEFAULT_OIDC_CLAIM_MAPPINGS.email,
    firstName:
      process.env["OIDC_CLAIM_FIRST_NAME"] ??
      envClaimMappings?.firstName ??
      secretsClaimMappings.firstName ??
      DEFAULT_OIDC_CLAIM_MAPPINGS.firstName,
    lastName:
      process.env["OIDC_CLAIM_LAST_NAME"] ??
      envClaimMappings?.lastName ??
      secretsClaimMappings.lastName ??
      DEFAULT_OIDC_CLAIM_MAPPINGS.lastName,
    avatarUrl:
      process.env["OIDC_CLAIM_AVATAR_URL"] ??
      envClaimMappings?.avatarUrl ??
      secretsClaimMappings.avatarUrl ??
      DEFAULT_OIDC_CLAIM_MAPPINGS.avatarUrl,
    emailVerified:
      process.env["OIDC_CLAIM_EMAIL_VERIFIED"] ??
      envClaimMappings?.emailVerified ??
      secretsClaimMappings.emailVerified ??
      DEFAULT_OIDC_CLAIM_MAPPINGS.emailVerified,
  };

  return {
    issuer: process.env["OIDC_ISSUER"] ?? secrets?.issuer ?? undefined,
    authorizationURL,
    tokenURL,
    userInfoURL,
    clientID,
    clientSecret,
    callbackURL:
      process.env["OIDC_CALLBACK_URL"] ??
      secrets?.callbackURL ??
      `${config.host}/api/v1/auth/oidc/callback`,
    scope: process.env["OIDC_SCOPE"] ?? secrets?.scope ?? "openid email profile",
    buttonLabel:
      process.env["OIDC_BUTTON_LABEL"] ?? secrets?.buttonLabel ?? "Sign in with OIDC",
    disableOtherAuth:
      (process.env["OIDC_DISABLE_OTHER_AUTH"] ??
        secrets?.disableOtherAuth?.toString() ??
        "true") !== "false",
    adminEmailsBypass,
    claimMappings,
    kratosAdminUrl:
      process.env["OIDC_KRATOS_ADMIN_URL"] ?? secrets?.kratosAdminUrl,
  };
}

export function getOidcConfig(config: Config): OidcConfig | undefined {
  return config.oidc;
}

export function isOidcEnabled(config: Config): boolean {
  return !!config.oidc;
}

export function isOidcAdminBypassEmail(
  config: Config,
  email: string
): boolean {
  const oidc = config.oidc;
  if (!oidc) {
    return false;
  }
  return oidc.adminEmailsBypass.includes(email.toLowerCase());
}
