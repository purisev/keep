import { InternalConfig } from "@/types/internal-config";
import { Session } from "next-auth";
import { KeepApiError, KeepApiReadOnlyError } from "./KeepApiError";
import { getApiUrlFromConfig } from "@/shared/lib/getApiUrlFromConfig";
import { getApiURL } from "@/utils/apiUrl";
import * as Sentry from "@sentry/nextjs";
import { getSession, signOut as signOutClient } from "next-auth/react";
import { GuestSession } from "@/types/auth";
import { AuthType } from "@/utils/authenticationType";

const READ_ONLY_ALLOWED_METHODS = ["GET", "OPTIONS"];
const READ_ONLY_ALWAYS_ALLOWED_URLS = [
  "/alerts/audit",
  "/alerts/facets/options",
  "/alerts/query",
  "/incidents/facets/options",
  "/workflows/query",
  "/workflows/facets/options",
];

interface ApiClientOptions {
  headers?: Record<string, string>;
}

// Shared by every ApiClient instance: a burst of parallel 401s (background
// polling on alerts, incidents, presets, health) must trigger at most one
// session renewal and at most one sign-out.
let sessionRenewal: Promise<Session | null> | null = null;
let signOutInFlight: Promise<void> | null = null;

function renewSession(): Promise<Session | null> {
  if (!sessionRenewal) {
    // Hits /api/auth/session, which runs the jwt callback and, when the access
    // token is expired, the refresh_token grant in auth.config.ts.
    sessionRenewal = getSession().finally(() => {
      sessionRenewal = null;
    });
  }
  return sessionRenewal;
}

// next-auth's signOut() defaults to redirect: true, which does a full page load
// and drops the user wherever the default redirect points - losing the filters,
// scroll position and open dialogs of the page they were working on. Sign out
// without that redirect and send them back to the same URL after logging in.
function signOutAndReturn(): Promise<void> {
  if (!signOutInFlight) {
    signOutInFlight = runSignOut().finally(() => {
      signOutInFlight = null;
    });
  }
  return signOutInFlight;
}

async function runSignOut() {
  const callbackUrl = window.location.href;
  try {
    await signOutClient({ redirect: false });
  } catch (error) {
    console.error("Error signing out:", error);
  }
  window.location.href = `/signin?callbackUrl=${encodeURIComponent(
    callbackUrl
  )}`;
}

export class ApiClient {
  private readonly isServer: boolean;
  private readonly additionalHeaders: Record<string, string>;

  constructor(
    private readonly session: Session | GuestSession | null,
    private readonly config: InternalConfig | null,
    options: ApiClientOptions = {}
  ) {
    this.isServer = typeof window === "undefined";
    this.additionalHeaders = options.headers || {};
  }

  isReady() {
    return !!this.session && !!this.config;
  }

  getHeaders() {
    if (!this.session || !this.session.accessToken) {
      throw new Error("No valid session or access token found");
    }
    // Guest session
    if (this.session.accessToken === "unauthenticated") {
      return this.additionalHeaders;
    }
    return {
      Authorization: `Bearer ${this.session.accessToken}`,
      "ngrok-skip-browser-warning": true,
      ...this.additionalHeaders,
    };
  }

  getToken() {
    return this.session?.accessToken;
  }

  getApiBaseUrl() {
    if (this.isServer) {
      return getApiURL();
    }
    const baseUrl = getApiUrlFromConfig(this.config);
    if (baseUrl.startsWith("/")) {
      return `${window.location.origin}${baseUrl}`;
    }
    return baseUrl;
  }

  async handleResponse(response: Response, url: string) {
    // Ensure that the fetch was successful
    if (!response.ok) {
      // if the response has detail field, throw the detail field
      if (response.headers.get("content-type")?.includes("application/json")) {
        const data = await response.json();
        if (response.status === 401) {
          // on server, middleware will handle the sign out
          if (!this.isServer) {
            // For OAUTH2PROXY auth, redirect to oauth2-proxy's sign_out endpoint
            if (this.config?.AUTH_TYPE === AuthType.OAUTH2PROXY) {
              window.location.href = "/oauth2/sign_out";
            } else {
              await signOutAndReturn();
            }
          }
          throw new KeepApiError(
            `${data.message || data.detail}`,
            url,
            `You probably just need to sign in again.`,
            data,
            response.status
          );
        }
        if (response.status === 403 && data.detail.includes("Read only")) {
          throw new KeepApiReadOnlyError(
            "Application is in read-only mode",
            url,
            "The application is currently in read-only mode. Modifications are not allowed.",
            { readOnly: true },
            403
          );
        } else {
          throw new KeepApiError(
            `${data.message || data.detail}`,
            url,
            `Please try again. If the problem persists, please contact support.`,
            data,
            response.status
          );
        }
      }
      throw new Error("An error occurred while fetching the data");
    }

    if (response.headers.get("content-length") === "0") {
      return null;
    }

    try {
      if (response.headers.get("content-type")?.includes("application/json")) {
        return await response.json();
      }
      return await response.text();
    } catch (error) {
      console.error(error);
      if (!this.config?.SENTRY_DISABLED) {
        Sentry.captureException(error);
      }
      return null;
    }
  }

  async request<T = any>(
    url: string,
    requestInit: RequestInit = {}
  ): Promise<T> {
    if (!this.config) {
      throw new Error("No config found");
    }

    // Add read-only check for modification requests
    if (
      this.config.READ_ONLY &&
      !READ_ONLY_ALLOWED_METHODS.includes(requestInit.method || "") &&
      !READ_ONLY_ALWAYS_ALLOWED_URLS.some((allowedUrl) =>
        url.startsWith(allowedUrl)
      )
    ) {
      throw new KeepApiReadOnlyError(
        "Application is in read-only mode",
        url,
        "The application is currently in read-only mode. Modifications are not allowed.",
        { readOnly: true },
        403
      );
    }

    const apiUrl = this.isServer
      ? getApiURL()
      : getApiUrlFromConfig(this.config);
    const fullUrl = apiUrl + url;

    const headers: Record<string, any> = {
      ...(this.getHeaders() as Record<string, any>),
      ...(requestInit.headers as Record<string, any>),
    };

    let response = await fetch(fullUrl, { ...requestInit, headers });

    // In the browser a 401 normally just means the OIDC access token expired
    // while the page was open. Renew it and replay the request once, so that
    // background polling does not throw the user out of the page instead.
    if (
      response.status === 401 &&
      !this.isServer &&
      this.config?.AUTH_TYPE !== AuthType.OAUTH2PROXY
    ) {
      const renewedToken = await this.renewAccessToken();
      if (renewedToken) {
        response = await fetch(fullUrl, {
          ...requestInit,
          headers: { ...headers, Authorization: `Bearer ${renewedToken}` },
        });
      }
    }

    return this.handleResponse(response, url);
  }

  // Returns a fresh bearer token if the session really was renewed, or null
  // when there is nothing better to retry with.
  private async renewAccessToken(): Promise<string | null> {
    const currentToken = this.session?.accessToken;
    if (!currentToken || currentToken === "unauthenticated") {
      return null;
    }
    try {
      const session = await renewSession();
      const renewedToken = session?.accessToken;
      // The same token back, or an explicit refresh failure, means the renewal
      // did not happen - replaying the request would only yield another 401.
      if (!renewedToken || session?.error || renewedToken === currentToken) {
        return null;
      }
      return renewedToken;
    } catch (error) {
      console.error("Error renewing session:", error);
      return null;
    }
  }

  async get<T = any>(url: string, requestInit: RequestInit = {}) {
    return this.request<T>(url, { method: "GET", ...requestInit });
  }

  async post<T = any>(
    url: string,
    data?: any,
    { headers, ...requestInit }: RequestInit = {}
  ) {
    return this.request<T>(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...headers,
      },
      body: data ? JSON.stringify(data) : undefined,
      ...requestInit,
    });
  }

  async put<T = any>(
    url: string,
    data?: any,
    { headers, ...requestInit }: RequestInit = {}
  ) {
    return this.request<T>(url, {
      method: "PUT",
      headers: {
        "Content-Type": "application/json",
        ...headers,
      },
      body: data ? JSON.stringify(data) : undefined,
      ...requestInit,
    });
  }

  async patch<T = any>(
    url: string,
    data?: any,
    { headers, ...requestInit }: RequestInit = {}
  ) {
    return this.request<T>(url, {
      method: "PATCH",
      headers: {
        "Content-Type": "application/json",
        ...headers,
      },
      body: data ? JSON.stringify(data) : undefined,
      ...requestInit,
    });
  }

  async delete<T = any>(
    url: string,
    data?: any,
    { headers, ...requestInit }: RequestInit = {}
  ) {
    return this.request<T>(url, {
      method: "DELETE",
      headers: {
        "Content-Type": "application/json",
        ...headers,
      },
      body: data ? JSON.stringify(data) : undefined,
      ...requestInit,
    });
  }
}
