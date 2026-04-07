import jwt from "jsonwebtoken"
import { authService } from "../services/authService.js"
import { tokenBlocklistService } from "../services/tokenBlocklistService.js"
import { successResponse } from "../utils/apiResponse.js"
import { AppError } from "../utils/appError.js"

export const authController = {
  /**
   * POST /auth/login
   * Validates credentials and returns a signed JWT + safe user object.
   */
  async login(req, res, next) {
    try {
      const result = await authService.login(
        req.body.username,
        req.body.password,
      )
      return successResponse(res, result, "Login successful")
    } catch (error) {
      next(error)
    }
  },

  /**
   * POST /auth/logout
   *
   * Requires a valid Bearer token (enforced by the `authenticate`
   * middleware that guards this route).
   *
   * Flow:
   *  1. Extract the raw JWT from the Authorization header.
   *  2. Decode (without re-verifying) to read the exp claim.
   *  3. Add the token to the in-memory blocklist so every subsequent
   *     request that presents this token is rejected with 401.
   *  4. Clear the http-only cookie used by Keycloak flows.
   *  5. Return 200 so the client knows it can safely discard its token.
   *
   * The client (frontend) MUST also remove the token from localStorage
   * after receiving this response.
   */
  async logout(req, res, next) {
    try {
      const header = req.headers.authorization || ""

      if (!header.startsWith("Bearer ")) {
        return next(new AppError("No token provided", 400))
      }

      const token = header.slice("Bearer ".length).trim()

      // jwt.decode does NOT verify the signature – the authenticate
      // middleware already verified the token before this controller ran.
      // We only need the exp claim to set the blocklist TTL.
      const decoded = jwt.decode(token)

      if (!decoded || typeof decoded !== "object") {
        return next(new AppError("Invalid token format", 400))
      }

      // exp is in seconds per the JWT spec; convert to milliseconds.
      const expMs = (decoded.exp ?? 0) * 1000
      tokenBlocklistService.add(token, expMs)

      // Clear the cookie that may have been set by the Keycloak flow.
      res.clearCookie("token", {
        httpOnly: true,
        secure: true,
        sameSite: "none",
      })

      return successResponse(res, null, "Logout successful")
    } catch (error) {
      next(error)
    }
  },

  /**
   * GET /auth/health
   * Simple liveness probe – no authentication required.
   */
  health(req, res) {
    return successResponse(res, { status: "UP" }, "Backend healthy")
  },
}
