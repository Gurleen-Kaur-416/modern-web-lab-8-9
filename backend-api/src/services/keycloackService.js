import crypto from "crypto";
import { createRemoteJWKSet, jwtVerify } from "jose";
import { AppError } from "../utils/appError.js";
import { keycloakConfig, validateKeycloakConfig } from "../config/keycloack.js";

validateKeycloakConfig();

const JWKS = createRemoteJWKSet(new URL(keycloakConfig.jwksUrl));

function extractRoleNames(payload) {
  const realmRoles = Array.isArray(payload?.realm_access?.roles)
    ? payload.realm_access.roles
    : [];

  const clientRoles = Array.isArray(
    payload?.resource_access?.[keycloakConfig.clientId]?.roles
  )
    ? payload.resource_access[keycloakConfig.clientId].roles
    : [];

  return [...new Set([...realmRoles, ...clientRoles])];
}

function mapKeycloakRoleToAppRole(roleName) {
  const normalized = String(roleName || "").trim().toLowerCase();

  const roleMap = {
    admin: "ADMIN",
    underwriter: "UNDERWRITER",
    agent: "AGENT",
    claims_adjuster: "CLAIMS_ADJUSTER",
    claimsadjuster: "CLAIMS_ADJUSTER",
    customer: "CUSTOMER"
  };

  return roleMap[normalized] || String(roleName || "").trim().toUpperCase();
}

export function generateState() {
  return crypto.randomBytes(24).toString("hex");
}

export function buildAuthorizationUrl(state) {
  const url = new URL(keycloakConfig.authorizationEndpoint);

  url.searchParams.set("client_id", keycloakConfig.clientId);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("scope", "openid profile email");
  url.searchParams.set("redirect_uri", keycloakConfig.backendCallbackUrl);
  url.searchParams.set("state", state);

  return url.toString();
}

export async function exchangeAuthorizationCode(code) {
  if (!code) {
    throw new AppError("Authorization code is required", 422);
  }

  const params = new URLSearchParams();
  params.set("grant_type", "authorization_code");
  params.set("client_id", keycloakConfig.clientId);
  params.set("client_secret", keycloakConfig.clientSecret);
  params.set("code", code);
  params.set("redirect_uri", keycloakConfig.backendCallbackUrl);

  const response = await fetch(keycloakConfig.tokenEndpoint, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded"
    },
    body: params.toString()
  });

  const data = await response.json();

  if (!response.ok) {
    throw new AppError(
      data?.error_description || data?.error || "Failed to exchange authorization code",
      401
    );
  }

  return data;
}

export async function verifyKeycloakAccessToken(token) {
  if (!token || typeof token !== "string") {
    throw new AppError("Missing Keycloak token", 401);
  }

  try {
    const { payload } = await jwtVerify(token, JWKS, {
      issuer: keycloakConfig.issuer
    });

    const mappedRoles = extractRoleNames(payload).map(mapKeycloakRoleToAppRole);

    return {
      authSource: "KEYCLOAK",
      sub: String(payload.sub || ""),
      username: payload.preferred_username ? String(payload.preferred_username) : "",
      email: payload.email ? String(payload.email) : "",
      fullName: payload.name ? String(payload.name) : "",
      givenName: payload.given_name ? String(payload.given_name) : "",
      familyName: payload.family_name ? String(payload.family_name) : "",
      roles: mappedRoles,
      rawTokenPayload: payload
    };
  } catch {
    throw new AppError("Invalid Keycloak token", 401);
  }
}