"use client";

import { Session } from "next-auth";
import { SessionProvider } from "next-auth/react";

type Props = {
  children?: React.ReactNode;
  session?: Session | null;
};

// How often the session is re-read from the server. Every read runs the jwt
// callback, which renews the access token shortly before it expires - that is
// what keeps a long-open tab from being signed out by the next background
// request. Must stay well under the shortest access token lifetime the IdP
// hands out.
const SESSION_REFETCH_INTERVAL_SECONDS = 5 * 60;

export const NextAuthProvider = ({ children, session }: Props) => {
  // Hydrate session on mount. The key has to be the one useHydratedSession
  // reads (window.__NEXT_AUTH.session) - it used to be written as
  // __NEXT_AUTH_SESSION__, which nothing read, so every page load waited on
  // /api/auth/session before the API client had a token.
  if (typeof window !== "undefined" && !!session) {
    window.__NEXT_AUTH = { ...window.__NEXT_AUTH, session };
  }

  return (
    <SessionProvider
      session={session}
      refetchInterval={SESSION_REFETCH_INTERVAL_SECONDS}
      refetchOnWindowFocus
    >
      {children}
    </SessionProvider>
  );
};
