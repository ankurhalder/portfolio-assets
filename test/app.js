/* eslint-disable global-require */
const path = require("path");
const express = require("express");
const pinoHttp = require("pino-http");
const rateLimit = require("express-rate-limit");
const helmet = require("helmet");
const mongoSanitize = require("express-mongo-sanitize");
const xss = require("xss-clean");
const hpp = require("hpp");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const Tokens = require("csrf");
const crypto = require("crypto");
const i18nextMiddleware = require("i18next-http-middleware");
const compression = require("compression");

const i18next = require("./config/i18n");
const logger = require("./utils/logger");
const AppError = require("./utils/appError");
const globalErrorHandler = require("./controllers/errorController");
const anomalyDetection = require("./middleware/anomalyDetection");
const apiMonitor = require("./middleware/apiMonitor");
const { CSRF_UNPROTECTED_ROUTES } = require("./config/constants");

const healthRouter = require("./routes/healthRoutes");
const adminRouter = require("./routes/adminRoutes");
const apiRouter = require("./routes/index");
const webhookRouter = require("./routes/webhookRoutes");
const debugController = require("./controllers/debugController");

const app = express();

app.use("/api/v1/webhooks", webhookRouter);

if (process.env.NODE_ENV !== "production") {
  app.post(
    "/api/v1/debug/test-login",
    express.json(),
    debugController.testAdminLogin,
  );
}

app.use(i18nextMiddleware.handle(i18next));

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

app.set("trust proxy", 1);

const tokens = new Tokens();
const csrfSecret =
  process.env.CSRF_SECRET || crypto.randomBytes(24).toString("hex");
const commonCorsOptions = {
  methods: "GET,POST,PUT,DELETE,PATCH,UPDATE,HEAD",
  allowedHeaders:
    "Origin, X-Requested-With, Content-Type, Accept, Authorization, x-csrf-token, Accept-Language, If-None-Match",
  credentials: true,
};

let corsOptions;
if (process.env.NODE_ENV === "production") {
  const allowedOrigins = process.env.ALLOWED_ORIGINS
    ? process.env.ALLOWED_ORIGINS.split(",")
    : [];
  corsOptions = {
    ...commonCorsOptions,
    origin: (origin, callback) => {
      if (allowedOrigins.indexOf(origin) !== -1 || !origin) {
        callback(null, true);
      } else {
        callback(new Error("Not allowed by CORS"));
      }
    },
  };
} else {
  corsOptions = { ...commonCorsOptions, origin: true };
}

app.use(cors(corsOptions));
app.options("*", cors(corsOptions));
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        ...helmet.contentSecurityPolicy.getDefaultDirectives(),
        "script-src": [
          "'self'",
          "https://cdn.tailwindcss.com",
          "https://unpkg.com",
          "https://cdn.jsdelivr.net",
          "'unsafe-inline'",
        ],
        "style-src": [
          "'self'",
          "'unsafe-inline'",
          "https://fonts.googleapis.com",
          "https://unpkg.com",
        ],
        "font-src": ["'self'", "https://fonts.gstatic.com"],
        "img-src": [
          "'self'",
          "data:",
          "https://placehold.co",
          process.env.ASSET_PROVIDER_DOMAIN,
          "https://*.tile.openstreetmap.org",
        ],
      },
    },
    crossOriginEmbedderPolicy: false,
  }),
);

app.use(pinoHttp({ logger }));

const apiLimiter = rateLimit({
  max: 1000,
  windowMs: 60 * 60 * 1000,
  message: "Too many requests from this IP, please try again in an hour!",
  standardHeaders: true,
  legacyHeaders: false,
});
app.use("/api/", apiLimiter);

app.use(anomalyDetection);

app.use(express.json({ limit: process.env.BODY_LIMIT || "15kb" }));
app.use(
  express.urlencoded({
    extended: true,
    limit: process.env.BODY_LIMIT || "15kb",
  }),
);
app.use(cookieParser());

app.use(compression());
app.use(mongoSanitize());
app.use(xss());
app.use(hpp());

app.use(express.static(path.join(__dirname, "public")));

const csrfProtection = (req, res, next) => {
  if (["GET", "HEAD", "OPTIONS"].includes(req.method)) return next();
  if (CSRF_UNPROTECTED_ROUTES.some((p) => req.originalUrl.startsWith(p)))
    return next();

  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith("Bearer ")
  )
    return next();

  const token = req.headers["x-csrf-token"];
  if (!token || !tokens.verify(csrfSecret, token))
    return next(
      new AppError(req.t("auth.invalidCsrf"), 403, "auth.invalidToken"),
    );
  next();
};

app.use(csrfProtection);

app.get("/api/v1/csrf-token", (req, res) => {
  const token = tokens.create(csrfSecret);
  res.status(200).json({ csrfToken: token });
});

app.use("/health", healthRouter);
app.use("/admin", adminRouter);
app.use("/api", apiMonitor, apiRouter);

app.all("*", (req, res, next) => {
  if (req.originalUrl.startsWith("/api")) {
    return next(
      new AppError(
        req.t("errors.notFound", { url: req.originalUrl }),
        404,
        "db.notFound",
      ),
    );
  }
  res.status(404).render("404", { title: "Page Not Found" });
});

app.use(globalErrorHandler);

module.exports = app;
