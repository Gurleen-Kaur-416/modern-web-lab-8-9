"use client"

import {
  createContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react"
import { apiRequest } from "@/lib/api"
import {
  clearAuth,
  getAuthMode,
  getStoredUser,
  getToken,
  saveAuth,
} from "@/lib/auth"
import type { User } from "@/types/user"
import type { LoginResponseData } from "@/types/auth"

interface AuthContextValue {
  user: User | null
  ready: boolean
  login: (username: string, password: string) => Promise<User>
  logout: () => Promise<void>
}

export const AuthContext = createContext<AuthContextValue | null>(null)

interface AuthProviderProps {
  children: ReactNode
}

const API_BASE_URL = process.env.NEXT_PUBLIC_API_BASE_URL

if (!API_BASE_URL) {
  throw new Error("Missing NEXT_PUBLIC_API_BASE_URL environment variable")
}

export function AuthProvider({ children }: AuthProviderProps) {
  const [user, setUser] = useState<User | null>(null)
  const [ready, setReady] = useState(false)

  useEffect(() => {
    const storedUser = getStoredUser()
    if (storedUser) {
      setUser(storedUser)
    }
    setReady(true)
  }, [])

  async function login(username: string, password: string): Promise<User> {
    const response = await apiRequest<LoginResponseData>("/auth/login", {
      method: "POST",
      body: { username, password },
    })

    saveAuth(response.data.token, response.data.user)
    setUser(response.data.user)

    return response.data.user
  }

  /**
   * Logout flow (three steps, all best-effort – local cleanup always runs):
   *
   * Step 1 – Server-side JWT revocation
   *   POST /auth/logout with the current Bearer token so the server adds
   *   it to the in-memory blocklist.  Any subsequent request with this
   *   token is rejected with 401 even before natural expiry.
   *
   * Step 2 – Keycloak session teardown (only for KEYCLOAK auth mode)
   *   Calls the backend Keycloak logout endpoint which invalidates the
   *   Keycloak session server-side and clears the session cookie.
   *
   * Step 3 – Local cleanup
   *   Removes the token, user, and auth-mode entries from localStorage
   *   and clears the in-memory React state.  This step always runs
   *   regardless of whether network calls succeeded.
   */
  async function logout(): Promise<void> {
    const authMode = getAuthMode()
    const token = getToken()

    // ── Step 1: Revoke the JWT on the backend ───────────────────────────
    if (token) {
      try {
        await fetch(`${API_BASE_URL}/auth/logout`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${token}`,
          },
          credentials: "include",
        })
      } catch {
        // Network failure – continue with local cleanup regardless.
      }
    }

    // ── Step 2: Keycloak session teardown ───────────────────────────────
    if (authMode === "KEYCLOAK") {
      try {
        await fetch(`${API_BASE_URL}/auth/keycloak/logout`, {
          method: "GET",
          credentials: "include",
        })
      } catch {
        // Ignore – local cleanup will still run.
      }
    }

    // ── Step 3: Clear all local auth state ──────────────────────────────
    clearAuth()
    setUser(null)
  }

  const value = useMemo<AuthContextValue>(
    () => ({
      user,
      ready,
      login,
      logout,
    }),
    [user, ready],
  )

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}
