import { AppError } from "../utils/appError.js";

function readEnv(name, fallback = "") {
  const value = process.env[name];
  if (typeof value === "string" && value.trim()) {
    return value.trim();
  }
  return fallback;
}

const baseUrl = readEnv("KEYCLOAK_BASE_URL");
const realm = readEnv("KEYCLOAK_REALM");
const issuer = readEnv(
  "KEYCLOAK_ISSUER",
  baseUrl && realm ? `${baseUrl}/realms/${realm}` : ""
);
const jwksUrl = readEnv(
  "KEYCLOAK_JWKS_URL",
  issuer ? `${issuer}/protocol/openid-connect/certs` : ""
);

export const keycloakConfig = {
  baseUrl,
  realm,
  issuer,
  jwksUrl,
  clientId: readEnv("KEYCLOAK_CLIENT_ID"),
  clientSecret: readEnv("KEYCLOAK_CLIENT_SECRET"),
  backendCallbackUrl: readEnv("KEYCLOAK_BACKEND_CALLBACK_URL"),
  frontendSuccessRedirectUrl: readEnv("KEYCLOAK_FRONTEND_SUCCESS_REDIRECT_URL"),
  frontendFailureRedirectUrl: readEnv("KEYCLOAK_FRONTEND_FAILURE_REDIRECT_URL"),
  authorizationEndpoint: issuer
    ? `${issuer}/protocol/openid-connect/auth`
    : "",
  tokenEndpoint: issuer
    ? `${issuer}/protocol/openid-connect/token`
    : "",
  logoutEndpoint: issuer
    ? `${issuer}/protocol/openid-connect/logout`
    : ""
};

export function validateKeycloakConfig() {
  const required = [
    "baseUrl",
    "realm",
    "issuer",
    "jwksUrl",
    "clientId",
    "clientSecret",
    "backendCallbackUrl",
    "frontendSuccessRedirectUrl",
    "frontendFailureRedirectUrl",
    "authorizationEndpoint",
    "tokenEndpoint"
  ];

  const missing = required.filter((key) => !keycloakConfig[key]);

  if (missing.length > 0) {
    throw new AppError(
      `Missing Keycloak configuration: ${missing.join(", ")}`,
      500
    );
  }
}