import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { env } from "./env.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const projectRoot = path.resolve(__dirname, "../..");

export function getHttpsOptions() {
  const pfx = fs.readFileSync(path.resolve(projectRoot, env.httpsPfxPath));

  return {
    pfx,
    passphrase: env.httpsPfxPassphrase
  };
}