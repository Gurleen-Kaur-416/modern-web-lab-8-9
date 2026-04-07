import jwt from "jsonwebtoken";
import { env } from "../config/env.js";

export const tokenService = {
  generateAccessToken(user) {
    return jwt.sign(
      {
        userId: String(user._id)
      },
      env.jwtSecret,
      { expiresIn: env.jwtExpiresIn }
    );
  }
};