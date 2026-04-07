import {
  buildAuthorizationUrl,
  exchangeAuthorizationCode,
  generateState,
  verifyKeycloakAccessToken
} from "../services/keycloackService.js";
import { findOrProvisionUserFromKeycloak } from "../services/userProvisioningService.js";
import { tokenService } from "../services/tokenService.js";
import { keycloakConfig } from "../config/keycloack.js";

const STATE_COOKIE_NAME = "kc_state";
const APP_TOKEN_COOKIE_NAME = "token";

function buildCookieOptions() {
  const isProduction = process.env.NODE_ENV === "production";

  return {
    httpOnly: true,
    sameSite: isProduction ? "none" : "lax",
    secure: isProduction,
    path: "/"
  };
}

export const keycloakController = {
  login(req, res, next) {
    try {
      const state = generateState();
      const redirectUrl = buildAuthorizationUrl(state);

      res.cookie(STATE_COOKIE_NAME, state, {
        ...buildCookieOptions(),
        maxAge: 10 * 60 * 1000
      });

      return res.redirect(redirectUrl);
    } catch (error) {
      return next(error);
    }
  },

  async callback(req, res) {
    try {
      const { code, state } = req.query;
      const expectedState = req.cookies?.[STATE_COOKIE_NAME];

      if (!code || typeof code !== "string") {
        return res.redirect(
          `${keycloakConfig.frontendFailureRedirectUrl}?error=missing_code`
        );
      }

      if (!state || typeof state !== "string" || !expectedState || state !== expectedState) {
        return res.redirect(
          `${keycloakConfig.frontendFailureRedirectUrl}?error=invalid_state`
        );
      }

      const tokenSet = await exchangeAuthorizationCode(code);
      const identity = await verifyKeycloakAccessToken(tokenSet.access_token);
      const localUser = await findOrProvisionUserFromKeycloak(identity);

      const appToken = tokenService.generateAccessToken(localUser);

      res.clearCookie(STATE_COOKIE_NAME, { path: "/" });

      res.cookie(APP_TOKEN_COOKIE_NAME, appToken, {
        ...buildCookieOptions(),
        maxAge: 24 * 60 * 60 * 1000
      });

      return res.redirect(keycloakConfig.frontendSuccessRedirectUrl);
    } catch (error) {
      return res.redirect(
        `${keycloakConfig.frontendFailureRedirectUrl}?error=keycloak_callback_failed`
      );
    }
  },

  logout(req, res) {
    res.clearCookie(APP_TOKEN_COOKIE_NAME, { path: "/" });
    res.clearCookie(STATE_COOKIE_NAME, { path: "/" });

    return res.redirect(keycloakConfig.frontendFailureRedirectUrl);
  }
};