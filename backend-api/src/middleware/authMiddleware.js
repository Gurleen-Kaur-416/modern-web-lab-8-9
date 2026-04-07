import jwt from "jsonwebtoken"
import { AppError } from "../utils/appError.js"
import { userRepository } from "../repositories/userRepository.js"
import { tokenBlocklistService } from "../services/tokenBlocklistService.js"
import { env } from "../config/env.js"

function getBearerToken(req) {
  const header = req.headers.authorization || ""

  if (header.startsWith("Bearer ")) {
    return header.slice("Bearer ".length).trim()
  }

  if (req.cookies?.token) {
    return String(req.cookies.token)
  }

  return ""
}

function getRoleNames(roles) {
  return (roles || []).map((role) => {
    if (typeof role === "string") {
      return role
    }

    if (role && typeof role === "object" && role.name) {
      return role.name
    }

    return String(role)
  })
}

async function authenticateLocal(req) {
  const token = getBearerToken(req)

  if (!token) {
    return null
  }

  // Reject tokens that were explicitly revoked via POST /auth/logout.
  // This check happens BEFORE signature verification to avoid unnecessary
  // cryptographic work for known-revoked tokens.
  if (tokenBlocklistService.has(token)) {
    return null
  }

  try {
    const decoded = jwt.verify(token, env.jwtSecret)

    if (!decoded?.userId) {
      return null
    }

    const user = await userRepository.findById(decoded.userId)

    if (!user) {
      return null
    }

    const normalizedUser =
      typeof user.toObject === "function" ? user.toObject() : user

    return {
      ...normalizedUser,
      _id: String(user._id),
      roles: getRoleNames(user.roles),
      authSource: "LOCAL",
    }
  } catch {
    return null
  }
}

export async function authenticate(req, res, next) {
  try {
    const localUser = await authenticateLocal(req)

    if (localUser) {
      req.user = localUser
      return next()
    }

    return next(new AppError("Unauthorized", 401))
  } catch (error) {
    return next(error)
  }
}
