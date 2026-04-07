import { createRemoteJWKSet, jwtVerify } from "jose";
import { env } from "../config/env.js";

function getBearerToken(req) {
  const header = req.headers.authorization || "";

  if (header.startsWith("Bearer ")) {
    return header.slice("Bearer ".length).trim();
  }

  return "";
}

function buildRoleList(payload) {
  const realmRoles = Array.isArray(payload?.realm_access?.roles)
    ? payload.realm_access.roles
    : [];

  const clientRoles = Array.isArray(
    payload?.resource_access?.[env.keycloakClientId]?.roles
  )
    ? payload.resource_access[env.keycloakClientId].roles
    : [];

  return [...new Set([...realmRoles, ...clientRoles])];
}

let jwks;

function getJwks() {
  if (!jwks) {
    const issuer = env.keycloakIssuer.replace(/\/$/, "");
    jwks = createRemoteJWKSet(
      new URL(`${issuer}/protocol/openid-connect/certs`)
    );
  }

  return jwks;
}

export async function authenticateWithKeycloak(req) {
  if (!env.keycloakEnabled) {
    return null;
  }

  const token = getBearerToken(req);
  if (!token) {
    return null;
  }

  try {
    const issuer = env.keycloakIssuer.replace(/\/$/, "");

    const { payload } = await jwtVerify(token, getJwks(), {
      issuer,
      audience: env.keycloakClientId
    });

    return {
      _id: String(payload.sub || ""),
      username: String(
        payload.preferred_username || payload.email || payload.sub || ""
      ),
      email: String(payload.email || ""),
      roles: buildRoleList(payload),
      authSource: "KEYCLOAK"
    };
  } catch {
    return null;
  }
}