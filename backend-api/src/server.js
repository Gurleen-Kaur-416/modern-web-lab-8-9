//import https from "https";
import http from "http"
import app from "./app.js";
import { env } from "./config/env.js";
import { connectDatabase } from "./config/db.js";
import { getHttpsOptions } from "./config/https.js";

async function startServer() {
  await connectDatabase();

  //const httpsServer = https.createServer(getHttpsOptions(), app);
  const httpsServer = http.createServer(getHttpsOptions(), app);


  httpsServer.listen(env.port, () => {
    console.log(`Secure backend API running on https://localhost:${env.port}`);
  });
}

startServer().catch((error) => {
  console.error("Failed to start server:", error);
  process.exit(1);
});