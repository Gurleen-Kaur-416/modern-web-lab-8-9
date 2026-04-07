import dotenv from "dotenv";

dotenv.config();

function requireEnv(name) {
  const value = process.env[name];
  if (!value || value.trim() === "") {
    throw new Error(`Missing required environment variable: ${name}`);
  }
  return value;
}

export const env = Object.freeze({
  nodeEnv: process.env.NODE_ENV || "development",
  port: Number(process.env.PORT || 5001),
  mongoUri: requireEnv("MONGODB_URI"),
  jwtSecret: requireEnv("JWT_SECRET"),
  jwtExpiresIn: process.env.JWT_EXPIRES_IN || "2h",
  frontendUrl: requireEnv("FRONTEND_URL"),
  httpsPfxPath: requireEnv("HTTPS_PFX_PATH"),
  httpsPfxPassphrase: requireEnv("HTTPS_PFX_PASSPHRASE")
});