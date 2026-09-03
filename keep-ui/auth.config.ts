import type {NextAuthConfig, User} from "next-auth";
import {AuthError} from "next-auth";
import Credentials from "next-auth/providers/credentials";
import Keycloak from "next-auth/providers/keycloak";
import Auth0 from "next-auth/providers/auth0";
import MicrosoftEntraID from "next-auth/providers/microsoft-entra-id";
import Okta from "next-auth/providers/okta";
import OneLogin from "next-auth/providers/onelogin";
import {AuthenticationError, AuthErrorCodes} from "@/errors";
import type {JWT} from "next-auth/jwt";
import type {Provider} from "next-auth/providers";
import {getApiURL} from "@/utils/apiUrl";
import {
  AuthType,
  MULTI_TENANT,
  NO_AUTH,
  NoAuthTenant,
  NoAuthUserEmail,
  SINGLE_TENANT,
} from "@/utils/authenticationType";
import {authorizeOAuth2Proxy} from "@/shared/lib/oauth2proxy-auth";

export class BackendRefusedError extends AuthError {
  static type = "BackendRefusedError";
}

// Read env vars via bracket notation to prevent webpack DefinePlugin from
// inlining them as `undefined` at build time.  This file is imported by
// middleware.ts (Edge Runtime) where DefinePlugin replaces direct
// `process.env.X` references with their build-time values.
function runtimeEnv(key: string): string | undefined {
  return process.env[key];
}

const authSessionTimeout = runtimeEnv("AUTH_SESSION_TIMEOUT")
  ? Number.parseInt(runtimeEnv("AUTH_SESSION_TIMEOUT")!)
  : 30 * 24 * 60 * 60; // Default to 30 days if not set
// Determine auth type with backward compatibility
const authTypeEnv = runtimeEnv("AUTH_TYPE");
export const authType =
  authTypeEnv === MULTI_TENANT
    ? AuthType.AUTH0
    : authTypeEnv === SINGLE_TENANT
      ? AuthType.DB
      : authTypeEnv === NO_AUTH
        ? AuthType.NOAUTH
        : // The backend spells it "oidc"; accept either casing.
          (authTypeEnv?.toUpperCase() as AuthType);

// An AUTH_TYPE the frontend does not know used to fall through to the NOAUTH
// provider further down, which silently let everyone in without an IdP and
// made the misconfiguration look like a CSRF bug. Fail loudly instead.
// An unset AUTH_TYPE still means NOAUTH, as documented.
if (authTypeEnv && !Object.values(AuthType).includes(authType)) {
  throw new Error(
    `Unsupported AUTH_TYPE ${JSON.stringify(authTypeEnv)}. Supported values: ` +
      Object.values(AuthType).join(", ")
  );
}

export const proxyUrl =
  process.env.HTTP_PROXY ||
  process.env.HTTPS_PROXY ||
  process.env.http_proxy ||
  process.env.https_proxy;

// Auth types whose access token can be renewed with a refresh_token grant.
const REFRESHABLE_AUTH_TYPES: AuthType[] = [
  AuthType.KEYCLOAK,
  AuthType.OKTA,
  AuthType.ONELOGIN,
  AuthType.AZUREAD,
  AuthType.AUTH0,
  AuthType.OIDC,
];

// --------------------------------------------------------------------------
// Generic OIDC (AUTH_TYPE=oidc)
//
// The counterpart of keep/identitymanager/identity_managers/oidc on the
// backend, and deliberately configured through the same KEEP_OIDC_* variables
// so one set of env vars describes both halves. The backend stays authoritative
// for authorization: it validates the bearer token against the IdP's JWKS and
// resolves the role itself. What is read here only drives the UI - which tenant
// to display and which role gates which page.
// --------------------------------------------------------------------------

// Which token Keep's backend receives as the bearer. On most IdPs the access
// token is a JWT, but not all of them (Auth0 issues an opaque one unless an API
// audience is requested), so this is configurable. It has to agree with
// KEEP_OIDC_AUDIENCE on the backend, since aud differs between the two tokens.
const oidcBearerTokenKind =
  runtimeEnv("KEEP_OIDC_BEARER_TOKEN")?.trim().toLowerCase() === "id_token"
    ? "id_token"
    : "access_token";

function oidcBearerToken(tokens: {
  access_token?: string | null;
  id_token?: string | null;
}): string | undefined {
  const token =
    oidcBearerTokenKind === "id_token" ? tokens.id_token : tokens.access_token;
  return token ?? undefined;
}

// Decoded, not verified - the backend does the verification that matters.
function decodeJwtClaims(token: string | undefined): Record<string, any> {
  const payload = token?.split(".")[1];
  if (!payload) {
    return {};
  }
  try {
    // base64url -> base64; the "base64url" encoding name is not available in
    // every runtime this callback runs in (it also runs in the Edge runtime).
    const base64 = payload.replace(/-/g, "+").replace(/_/g, "/");
    return JSON.parse(Buffer.from(base64, "base64").toString());
  } catch (error) {
    console.warn("Failed to decode OIDC token claims:", error);
    return {};
  }
}

// Dotted claim path, same notation as the KEEP_OIDC_*_CLAIM variables.
function readClaim(claims: Record<string, any>, path: string): any {
  return path
    .split(".")
    .reduce(
      (node: any, part) =>
        node && typeof node === "object" ? node[part] : undefined,
      claims
    );
}

// Providers disagree on the shape of a groups claim: a JSON array, a single
// string, or a comma-separated string. Mirrors _as_list() on the backend.
function claimAsList(value: any): string[] {
  if (typeof value === "string") {
    return value
      .split(",")
      .map((item) => item.trim())
      .filter(Boolean);
  }
  if (Array.isArray(value)) {
    return value.map((item) => String(item).trim()).filter(Boolean);
  }
  return [];
}

// Only the inline JSON form; KEEP_OIDC_ROLE_MAPPINGS_FILE is backend-only,
// because this runs in the Edge runtime where there is no filesystem.
function oidcRoleMappings(): { group: string; role: string }[] {
  const inline = runtimeEnv("KEEP_OIDC_ROLE_MAPPINGS")?.trim();
  if (!inline) {
    return [];
  }
  try {
    const parsed = JSON.parse(inline);
    const entries = Array.isArray(parsed) ? parsed : (parsed?.mappings ?? []);
    return entries.filter((entry: any) => entry?.group && entry?.role);
  } catch (error) {
    console.error("Cannot parse KEEP_OIDC_ROLE_MAPPINGS as JSON:", error);
    return [];
  }
}

// Mirrors OidcAuthVerifier._resolve_role: an explicit role claim wins, then the
// ordered group mappings, then the configured default.
// KEEP_OIDC_ROLE_COMPOSITION=union is not reproduced - a composite role only
// changes what the backend returns, which it works out on its own.
function resolveOidcRole(claims: Record<string, any>): string | undefined {
  const roleClaim = runtimeEnv("KEEP_OIDC_ROLE_CLAIM")?.trim();
  if (roleClaim) {
    const value = readClaim(claims, roleClaim);
    const roleName = Array.isArray(value) ? value[0] : value;
    if (roleName) {
      return String(roleName);
    }
  }

  const groups = claimAsList(
    readClaim(claims, runtimeEnv("KEEP_OIDC_GROUPS_CLAIM") || "groups")
  );
  for (const { group, role } of oidcRoleMappings()) {
    if (groups.includes(group)) {
      return role;
    }
  }

  return runtimeEnv("KEEP_OIDC_DEFAULT_ROLE")?.trim() || undefined;
}

function oidcIssuer(): string {
  return (runtimeEnv("KEEP_OIDC_ISSUER") || "").replace(/\/$/, "");
}

// Discovered once per process: the refresh grant needs the token endpoint, and
// unlike the provider itself this call is not routed through Auth.js.
let discoveredOidcTokenEndpoint: string | undefined;

async function oidcTokenEndpoint(): Promise<string> {
  const configured = runtimeEnv("KEEP_OIDC_TOKEN_URL")?.trim();
  if (configured) {
    return configured;
  }
  if (discoveredOidcTokenEndpoint) {
    return discoveredOidcTokenEndpoint;
  }
  const url = `${oidcIssuer()}/.well-known/openid-configuration`;
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(
      `OIDC discovery failed for ${url}: ${response.status} ${response.statusText}. ` +
        "Set KEEP_OIDC_TOKEN_URL to skip discovery."
    );
  }
  const metadata = await response.json();
  if (!metadata.token_endpoint) {
    throw new Error(`No token_endpoint in provider metadata at ${url}`);
  }
  const endpoint = metadata.token_endpoint as string;
  discoveredOidcTokenEndpoint = endpoint;
  return endpoint;
}

// These providers hand Keep the id_token as the bearer token instead of the
// access token (see the jwt callback below), so the refreshed pair has to be
// picked the same way.
const ID_TOKEN_AS_ACCESS_TOKEN: AuthType[] = [
  AuthType.AUTH0,
  AuthType.ONELOGIN,
];

// Renew a bit before the real expiry so an in-flight request never races it.
const ACCESS_TOKEN_REFRESH_SKEW_MS = 60 * 1000;

// offline_access is what makes the IdP issue a refresh_token in the first
// place. Keycloak hands one out without it (and asking would turn it into a
// long-lived offline token), so it is only requested where the IdP needs it.
// Escape hatch for IdPs configured to reject the scope.
const requestOfflineAccess =
  runtimeEnv("AUTH_DISABLE_OFFLINE_ACCESS") !== "true";

function withOfflineAccess(scope: string): string {
  return requestOfflineAccess ? `${scope} offline_access` : scope;
}

function azureAdScope(): string {
  return withOfflineAccess(
    `api://${process.env.KEEP_AZUREAD_CLIENT_ID!}/default openid profile email`
  );
}

async function refreshAccessToken(token: any) {
  let issuerUrl = "";
  let clientId = "";
  let clientSecret = "";
  let refreshTokenUrl = "";
  let scope = "";

  switch (authType) {
    case AuthType.KEYCLOAK: {
      issuerUrl = process.env.KEYCLOAK_ISSUER || "";
      clientId = process.env.KEYCLOAK_ID || "";
      clientSecret = process.env.KEYCLOAK_SECRET || "";
      refreshTokenUrl = `${issuerUrl}/protocol/openid-connect/token`;
      break;
    }
    case AuthType.OKTA: {
      issuerUrl = process.env.OKTA_ISSUER || "";
      clientId = process.env.OKTA_CLIENT_ID || "";
      clientSecret = process.env.OKTA_CLIENT_SECRET || "";
      refreshTokenUrl = `${issuerUrl}/v1/token`;
      break;
    }
    case AuthType.ONELOGIN: {
      issuerUrl = process.env.ONELOGIN_ISSUER || "";
      clientId = process.env.ONELOGIN_CLIENT_ID || "";
      clientSecret = process.env.ONELOGIN_CLIENT_SECRET || "";
      refreshTokenUrl = `${issuerUrl}/token`;
      break;
    }
    case AuthType.AZUREAD: {
      // NOTE: when HTTP_PROXY is set, the provider itself is proxied via
      // customFetch in auth.ts, but this call is not - it goes out directly.
      clientId = process.env.KEEP_AZUREAD_CLIENT_ID || "";
      clientSecret = process.env.KEEP_AZUREAD_CLIENT_SECRET || "";
      refreshTokenUrl = `https://login.microsoftonline.com/${process.env
        .KEEP_AZUREAD_TENANT_ID!}/oauth2/v2.0/token`;
      // Entra ID requires the scope to be repeated on the refresh grant.
      scope = azureAdScope();
      break;
    }
    case AuthType.AUTH0: {
      issuerUrl = (process.env.AUTH0_ISSUER || "").replace(/\/$/, "");
      clientId = process.env.AUTH0_CLIENT_ID || "";
      clientSecret = process.env.AUTH0_CLIENT_SECRET || "";
      refreshTokenUrl = `${issuerUrl}/oauth/token`;
      break;
    }
    case AuthType.OIDC: {
      clientId = process.env.KEEP_OIDC_CLIENT_ID || "";
      clientSecret = process.env.KEEP_OIDC_CLIENT_SECRET || "";
      // refreshTokenUrl comes from discovery, resolved inside the try below so
      // that a discovery failure is reported as a refresh error instead of
      // being thrown out of the jwt callback.
      break;
    }
    default: {
      throw new Error("Refresh token not supported for this auth type");
    }
  }

  try {
    if (authType === AuthType.OIDC) {
      refreshTokenUrl = await oidcTokenEndpoint();
    }

    const body = new URLSearchParams({
      client_id: clientId,
      client_secret: clientSecret,
      grant_type: "refresh_token",
      refresh_token: token.refreshToken,
    });
    if (scope) {
      body.set("scope", scope);
    }

    const response = await fetch(refreshTokenUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body,
    });

    const refreshedTokens = await response.json();

    if (!response.ok) {
      throw new Error(
        `Refresh token failed: ${response.status} ${response.statusText} ${
          refreshedTokens?.error_description ?? refreshedTokens?.error ?? ""
        }`
      );
    }

    const accessToken =
      authType === AuthType.OIDC
        ? oidcBearerToken(refreshedTokens)
        : ID_TOKEN_AS_ACCESS_TOKEN.includes(authType)
          ? refreshedTokens.id_token
          : refreshedTokens.access_token;

    if (!accessToken) {
      throw new Error("Refresh token response did not contain a usable token");
    }

    return {
      ...token,
      accessToken,
      accessTokenExpires: Date.now() + (refreshedTokens.expires_in || 3600) * 1000,
      refreshToken: refreshedTokens.refresh_token ?? token.refreshToken,
      error: undefined,
    };
  } catch (error) {
    console.error("Error refreshing access token:", error);
    return {
      ...token,
      error: "RefreshAccessTokenError",
    };
  }
}


// Base provider configurations without AzureAD
const baseProviderConfigs = {
  [AuthType.AUTH0]: [
    Auth0({
      clientId: process.env.AUTH0_CLIENT_ID!,
      clientSecret: process.env.AUTH0_CLIENT_SECRET!,
      issuer: process.env.AUTH0_ISSUER!,
      authorization: {
        params: {
          prompt: "login",
          scope: withOfflineAccess("openid email profile"),
        },
      },
    }),
  ],
  [AuthType.DB]: [
    Credentials({
      name: "Credentials",
      credentials: {
        username: { label: "Username", type: "text", placeholder: "keep" },
        password: { label: "Password", type: "password", placeholder: "keep" },
      },
      async authorize(credentials): Promise<User | null> {
        try {
          const response = await fetch(`${getApiURL()}/signin`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(credentials),
          });

          if (!response.ok) {
            const errorData = await response.json().catch(() => ({}));
            console.error("Authentication failed:", errorData);
            throw new AuthenticationError(AuthErrorCodes.INVALID_CREDENTIALS);
          }

          const user = await response.json();
          if (!user.accessToken) return null;

          return {
            id: user.id,
            name: user.name,
            email: user.email,
            accessToken: user.accessToken,
            tenantId: user.tenantId,
            role: user.role,
          };
        } catch (error) {
          if (error instanceof TypeError && error.message === "fetch failed") {
            throw new AuthenticationError(AuthErrorCodes.CONNECTION_REFUSED);
          }

          if (error instanceof AuthenticationError) {
            throw error;
          }

          throw new AuthenticationError(AuthErrorCodes.SERVICE_UNAVAILABLE);
        }
      },
    }),
  ],
  [AuthType.NOAUTH]: [
    Credentials({
      name: "NoAuth",
      credentials: {},
      async authorize(credentials): Promise<User> {
        // Extract tenantId from callbackUrl if present
        let tenantId = NoAuthTenant;
        let name = "Keep";

        if (
          credentials &&
          typeof credentials === "object" &&
          "callbackUrl" in credentials
        ) {
          const callbackUrl = credentials.callbackUrl as string;
          const url = new URL(callbackUrl, "http://localhost");
          const urlTenantId = url.searchParams.get("tenantId");

          if (urlTenantId) {
            tenantId = urlTenantId;
            name += ` (${tenantId})`;
            console.log("Using tenantId from callbackUrl:", tenantId);
          }
        }

        return {
          id: "keep-user-for-no-auth-purposes",
          name: name,
          email: NoAuthUserEmail,
          accessToken: JSON.stringify({
            tenant_id: tenantId,
            user_id: "keep-user-for-no-auth-purposes",
          }),
          tenantIds: [
            {
              tenant_id: "keep",
              tenant_name: "Tenant of Keep (tenant_id: keep)",
            },
            {
              tenant_id: "keep2",
              tenant_name: "Tenant of another Keep (tenant_id: keep2)",
            },
          ],
          tenantId: tenantId,
          role: "user",
        };
      },
    }),
  ],
  [AuthType.OAUTH2PROXY]: [
    Credentials({
      name: "OAuth2Proxy",
      credentials: {},
      async authorize(credentials, request): Promise<User | null> {
        return authorizeOAuth2Proxy(request.headers);
      },
    }),
  ],
  [AuthType.KEYCLOAK]: [
    Keycloak({
      clientId: process.env.KEYCLOAK_ID!,
      clientSecret: process.env.KEYCLOAK_SECRET!,
      issuer: process.env.KEYCLOAK_ISSUER,
      authorization: {
        params: {
          scope: "openid email profile",
        },
      },
      checks: ["pkce"],
    }),
  ],
  [AuthType.OKTA]: [
    Okta({
      clientId: process.env.OKTA_CLIENT_ID!,
      clientSecret: process.env.OKTA_CLIENT_SECRET!,
      issuer: process.env.OKTA_ISSUER!,
      authorization: {
        params: { scope: withOfflineAccess("openid email profile") },
      },
    }),
  ],
  [AuthType.ONELOGIN]: [
    OneLogin({
      clientId: process.env.ONELOGIN_CLIENT_ID!,
      clientSecret: process.env.ONELOGIN_CLIENT_SECRET!,
      issuer: process.env.ONELOGIN_ISSUER!,
      authorization: {
        params: { scope: withOfflineAccess("openid email profile groups") },
      },
    }),
  ],
  [AuthType.OIDC]: [
    {
      id: "oidc",
      name: process.env.KEEP_OIDC_DISPLAY_NAME || "SSO",
      type: "oidc" as const,
      // Auth.js discovers the authorization, token and userinfo endpoints from
      // the issuer, the same metadata document the backend uses for JWKS.
      issuer: oidcIssuer(),
      clientId: process.env.KEEP_OIDC_CLIENT_ID!,
      clientSecret: process.env.KEEP_OIDC_CLIENT_SECRET!,
      authorization: {
        params: {
          scope: withOfflineAccess(
            process.env.KEEP_OIDC_SCOPES || "openid email profile"
          ),
        },
      },
      client: {
        token_endpoint_auth_method:
          process.env.KEEP_OIDC_TOKEN_AUTH_METHOD || "client_secret_post",
      },
      checks: ["pkce", "state"],
      profile(profile: any, tokens: any) {
        const emailClaim = process.env.KEEP_OIDC_EMAIL_CLAIM || "email";
        const email =
          readClaim(profile, emailClaim) ||
          profile.preferred_username ||
          profile.sub;
        return {
          id: profile.sub,
          name: profile.name || profile.preferred_username || email,
          email,
          image: null,
          accessToken: oidcBearerToken(tokens) ?? "",
        };
      },
    },
  ] as Provider[],
  [AuthType.AZUREAD]: [
    MicrosoftEntraID({
      clientId: process.env.KEEP_AZUREAD_CLIENT_ID!,
      clientSecret: process.env.KEEP_AZUREAD_CLIENT_SECRET!,
      issuer: `https://login.microsoftonline.com/${process.env
        .KEEP_AZUREAD_TENANT_ID!}/v2.0`,
      authorization: {
        params: {
          scope: azureAdScope(),
        },
      },
      client: {
        token_endpoint_auth_method: "client_secret_post",
      },
    }),
  ],
};

let isDebug =
  process.env.AUTH_DEBUG == "true" || process.env.NODE_ENV === "development";
if (isDebug) {
  console.log("Auth debug mode enabled");
}

export const config = {
  debug: isDebug,
  trustHost: true,
  providers:
    baseProviderConfigs[authType as keyof typeof baseProviderConfigs] ||
    baseProviderConfigs[AuthType.NOAUTH],
  pages: {
    signIn: "/signin",
    error: "/error",
  },
  session: {
    strategy: "jwt" as const,
    maxAge: authSessionTimeout, // 30 days
  },
  callbacks: {
    authorized({ auth, request: { nextUrl } }) {
      const isLoggedIn = !!auth?.user;
      const isOnDashboard = nextUrl.pathname.startsWith("/dashboard");
      if (isOnDashboard) {
        return isLoggedIn;
      }
      return true;
    },
    jwt: async ({ token, user, account, profile }): Promise<JWT> => {
      if (account && user) {
        let accessToken: string | undefined;
        let tenantId: string | undefined = user.tenantId;
        let role: string | undefined = user.role;

        // if the account is from tenant-switch provider, return the token
        if (account.provider === "tenant-switch") {
          token.accessToken = user.accessToken;
          token.tenantId = user.tenantId;
          token.role = user.role;
          return token;
        }

        if (authType === AuthType.AZUREAD) {
          accessToken = account.access_token;
          if (account.id_token) {
            try {
              const payload = decodeJwtClaims(account.id_token);
              role = payload.roles?.[0] || "user";
              tenantId = payload.tid || undefined;
            } catch (e) {
              console.warn("Failed to decode id_token:", e);
            }
          }
        } else if (authType == AuthType.AUTH0) {
          accessToken = account.id_token;
          if ((profile as any)?.keep_tenant_id) {
            tenantId = (profile as any).keep_tenant_id;
          }
          if ((profile as any)?.keep_role) {
            role = (profile as any).keep_role;
          }
          // more than one tenants
          if ((profile as any)?.keep_tenant_ids) {
            user.tenantIds = (profile as any).keep_tenant_ids;
          }
        } else if (authType === AuthType.KEYCLOAK) {
          // TODO: remove this once we have a proper way to get the tenant id
          tenantId = (profile as any).keep_tenant_id || "keep";
          role = (profile as any).keep_role;
          accessToken = account.access_token;
        } else if (authType === AuthType.OKTA) {
          // Extract tenant and role from Okta token
          tenantId = (profile as any).keep_tenant_id || "keep";
          role = (profile as any).keep_role || "user";
          accessToken = account.access_token;
        } else if (authType === AuthType.OIDC) {
          accessToken = oidcBearerToken(account);
          // The backend re-derives both from the same claims; these copies only
          // drive the UI (tenant display, role-gated routes).
          const claims = decodeJwtClaims(accessToken);
          tenantId =
            readClaim(
              claims,
              process.env.KEEP_OIDC_TENANT_CLAIM || "keep_tenant_id"
            ) || "keep";
          role = resolveOidcRole(claims) || "user";
        } else if (authType === AuthType.ONELOGIN) {
          // Extract tenant and role from OneLogin token - use ID token for user data
          tenantId = (profile as any).keep_tenant_id || "keep";
          role = (profile as any).keep_role || "user";
          accessToken = account.id_token; // Use ID token instead of access token
        } else {
          accessToken =
            user.accessToken || account.access_token || account.id_token;
        }
        if (!accessToken) {
          throw new Error("No access token available");
        }

        token.accessToken = accessToken;
        token.tenantId = tenantId;
        token.role = role;

        if (authType === AuthType.KEYCLOAK) {
          accessToken = account.access_token;

          // If user object has tenantIds from profile parsing, include them
          if (user.tenantIds) {
            token.tenantIds = user.tenantIds;
          }

          // Set default tenant and role
          token.tenantId = user.tenantId || "keep";
          token.role = user.role || "user";

          // New code: Check if multi-org mode is enabled
          if (process.env.KEYCLOAK_ROLES_FROM_GROUPS === "true") {
            try {
              // Fetch organizations from backend API
              const response = await fetch(`${getApiURL()}/auth/user/orgs`, {
                method: "GET",
                headers: {
                  "Content-Type": "application/json",
                  Authorization: `Bearer ${accessToken}`,
                },
              });

              if (response.ok) {
                const orgDict = await response.json();

                // Create a properly typed array (not undefined)
                const tenantArr: {
                  tenant_id: string;
                  tenant_name: string;
                  tenant_logo_url?: string;
                }[] = [];

                // Populate the array with tenant data, handling null/undefined values
                Object.entries(orgDict).forEach(([org_name, orgData]) => {
                  const tenantObject: {
                    tenant_id: string;
                    tenant_name: string;
                    tenant_logo_url?: string;
                  } = {
                    tenant_id: String((orgData as any).tenant_id),
                    tenant_name: `${org_name}`,
                  };

                  // Only add tenant_logo_url if it exists and is not null
                  const logoUrl = (orgData as any).tenant_logo_url;
                  if (logoUrl !== null && logoUrl !== undefined) {
                    tenantObject.tenant_logo_url = logoUrl;
                  }

                  tenantArr.push(tenantObject);
                });

                // Only assign if we have entries (avoids undefined)
                if (tenantArr.length > 0) {
                  token.tenantIds = tenantArr;

                  // Set default tenant to the first one if available
                  token.tenantId = tenantArr[0].tenant_id || token.tenantId;

                  console.log("Successfully processed user orgs:", tenantArr);
                } else {
                  console.warn("No orgs returned from /auth/user/orgs");
                }
              } else {
                console.error(
                  "Failed to fetch user orgs:",
                  response.statusText
                );
              }
            } catch (error) {
              console.error("Error fetching user orgs:", error);
            }
          }
        }

        // Keep what is needed to renew the access token later on
        if (REFRESHABLE_AUTH_TYPES.includes(authType)) {
          token.refreshToken = account.refresh_token;
          token.accessTokenExpires = account.expires_at
            ? (account.expires_at as number) * 1000
            : Date.now() + (((account.expires_in as number) || 3600) * 1000);
        }
      } else if (
        REFRESHABLE_AUTH_TYPES.includes(authType) &&
        token.refreshToken &&
        token.accessTokenExpires &&
        typeof token.accessTokenExpires === "number" &&
        Date.now() > token.accessTokenExpires - ACCESS_TOKEN_REFRESH_SKEW_MS
      ) {
        // Runs on every session read, so an open tab renews its token in the
        // background instead of being signed out the moment it expires.
        // A failure is reported through token.error (see the session callback)
        // rather than thrown, so the session survives a transient IdP hiccup.
        token = await refreshAccessToken(token);
      }

      return token;
    },
    session: async ({ session, token, user }) => {
      return {
        ...session,
        // Surfaced so the client can react to a dead refresh token instead of
        // waiting for the backend to answer 401.
        error: token.error as string | undefined,
        accessToken: token.accessToken as string,
        tenantId: token.tenantId as string,
        userRole: token.role as string,
        user: {
          ...session.user,
          accessToken: token.accessToken as string,
          tenantId: token.tenantId as string,
          role: token.role as string,
          tenantIds: token.tenantIds || [],
        },
      };
    },
  },
} satisfies NextAuthConfig;

if (isDebug && authType === AuthType.AZUREAD && proxyUrl) {
  // add cookies override for AzureAD
  (config as any).cookies = {
    pkceCodeVerifier: {
      name: "authjs.pkce.code_verifier",
      options: {
        httpOnly: true,
        sameSite: "lax",
        path: "/",
        secure: false,
      },
    },
  };
}

// if debug is enabled, log the config
if (isDebug) {
  console.log("Auth config:", config);
}
