import express from "express";
import cors from "cors";
import helmet from "helmet";
import morgan from "morgan";
import cookieParser from "cookie-parser";
import { corsOptions } from "./config/cors.js";
import { appConfig } from "./config/appConfig.js";
import apiRoutes from "./routes/index.js";
import { requestLogger } from "./middleware/requestLoggerMiddleware.js";
import { notFoundMiddleware } from "./middleware/notFoundMiddleware.js";
import { errorMiddleware } from "./middleware/errorMiddleware.js";

const app = express();

app.use(helmet());
app.use(cors(corsOptions));
app.use(cookieParser());
app.use(express.json());
app.use(morgan("dev"));
app.use(requestLogger);

app.use(appConfig.apiPrefix, apiRoutes);

app.use(notFoundMiddleware);
app.use(errorMiddleware);

export default app;