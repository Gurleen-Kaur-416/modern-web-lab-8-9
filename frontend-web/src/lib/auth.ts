import { STORAGE_KEYS } from "./constants";
import type { User } from "@/types/user";

export type AuthMode = "LOCAL" | "KEYCLOAK";

export function saveAuth(token: string, user: User): void {
  if (typeof window === "undefined") return;

  localStorage.setItem(STORAGE_KEYS.token, token);
  localStorage.setItem(STORAGE_KEYS.user, JSON.stringify(user));
  localStorage.setItem(STORAGE_KEYS.authMode, "LOCAL");
}

export function saveKeycloakSession(user: User): void {
  if (typeof window === "undefined") return;

  localStorage.removeItem(STORAGE_KEYS.token);
  localStorage.setItem(STORAGE_KEYS.user, JSON.stringify(user));
  localStorage.setItem(STORAGE_KEYS.authMode, "KEYCLOAK");
}

export function clearAuth(): void {
  if (typeof window === "undefined") return;

  localStorage.removeItem(STORAGE_KEYS.token);
  localStorage.removeItem(STORAGE_KEYS.user);
  localStorage.removeItem(STORAGE_KEYS.authMode);
}

export function getToken(): string | null {
  if (typeof window === "undefined") return null;
  return localStorage.getItem(STORAGE_KEYS.token);
}

export function getStoredUser(): User | null {
  if (typeof window === "undefined") return null;

  const value = localStorage.getItem(STORAGE_KEYS.user);
  if (!value) return null;

  try {
    return JSON.parse(value) as User;
  } catch {
    return null;
  }
}

export function getAuthMode(): AuthMode | null {
  if (typeof window === "undefined") return null;

  const value = localStorage.getItem(STORAGE_KEYS.authMode);

  if (value === "LOCAL" || value === "KEYCLOAK") {
    return value;
  }

  return null;
}