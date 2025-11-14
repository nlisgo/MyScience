import * as client from "openid-client";
import { Strategy, type VerifyFunction } from "openid-client/passport";

import passport from "passport";
import session from "express-session";
import type { Express, RequestHandler } from "express";
import memoize from "memoizee";
import connectPg from "connect-pg-simple";
import { storage } from "./storage";
import { checkAndAwardBadges } from "./gamification";

const getOidcConfig = memoize(
  async () => {
    return await client.discovery(
      new URL(process.env.ISSUER_URL ?? "https://replit.com/oidc"),
      process.env.REPL_ID!
    );
  },
  { maxAge: 3600 * 1000 }
);

export function getSession() {
  const sessionTtl = 7 * 24 * 60 * 60 * 1000; // 1 week
  const pgStore = connectPg(session);
  const sessionStore = new pgStore({
    conString: process.env.DATABASE_URL,
    createTableIfMissing: false,
    ttl: sessionTtl,
    tableName: "sessions",
  });

  // Allow overriding secure cookie setting via environment variable for local development
  const isSecure = process.env.SECURE_COOKIES === "false" ? false : process.env.NODE_ENV === "production";
  console.log(`Session cookie secure setting: ${isSecure} (NODE_ENV: ${process.env.NODE_ENV}, SECURE_COOKIES: ${process.env.SECURE_COOKIES})`);

  return session({
    secret: process.env.SESSION_SECRET!,
    store: sessionStore,
    resave: false,
    saveUninitialized: true, // Changed to true to save new sessions
    cookie: {
      httpOnly: true,
      secure: isSecure,
      maxAge: sessionTtl,
    },
  });
}

function updateUserSession(
  user: any,
  tokens: client.TokenEndpointResponse & client.TokenEndpointResponseHelpers
) {
  user.claims = tokens.claims();
  user.access_token = tokens.access_token;
  user.refresh_token = tokens.refresh_token;
  user.expires_at = user.claims?.exp;
}

async function upsertUser(
  claims: any,
) {
  await storage.upsertUser({
    id: claims["sub"],
    email: claims["email"],
    firstName: claims["first_name"],
    lastName: claims["last_name"],
    profileImageUrl: claims["profile_image_url"],
  });
}

export async function setupAuth(app: Express) {
  app.set("trust proxy", 1);
  app.use(getSession());
  app.use(passport.initialize());
  app.use(passport.session());

  // Skip OIDC setup if REPL_ID is not provided (local development)
  if (!process.env.REPL_ID) {
    console.log("⚠️  REPL_ID not set - Using mock authentication for local development");

    // Mock authentication routes for local development
    app.get("/api/login", async (req, res) => {
      console.log("Mock login initiated");

      // Create a mock user session
      const mockUser = {
        claims: {
          sub: "local-dev-user",
          email: "dev@localhost",
          first_name: "Dev",
          last_name: "User",
          profile_image_url: "https://avatar.vercel.sh/dev"
        },
        access_token: "mock-token",
        refresh_token: "mock-refresh",
        expires_at: Math.floor(Date.now() / 1000) + 3600
      };

      try {
        // Upsert mock user to database first
        await storage.upsertUser({
          id: mockUser.claims.sub,
          email: mockUser.claims.email,
          firstName: mockUser.claims.first_name,
          lastName: mockUser.claims.last_name,
          profileImageUrl: mockUser.claims.profile_image_url,
        });
        console.log("Mock user created in database");

        // Set up user in session
        (req as any).login(mockUser, (err: any) => {
          if (err) {
            console.error("Login error:", err);
            return res.status(500).json({ error: "Login failed", details: err.message });
          }

          // Explicitly save the session before redirecting
          (req as any).session.save((saveErr: any) => {
            if (saveErr) {
              console.error("Session save error:", saveErr);
              return res.status(500).json({ error: "Session save failed" });
            }

            console.log("Mock user logged in, session created and saved");
            res.redirect("/");
          });
        });
      } catch (error) {
        console.error("Error during mock login:", error);
        res.status(500).json({ error: "Login failed" });
      }
    });

    app.get("/api/logout", (req, res) => {
      req.logout(() => {
        res.redirect("/");
      });
    });

    // Debug endpoint to check session
    app.get("/api/debug/session", (req, res) => {
      res.json({
        isAuthenticated: req.isAuthenticated(),
        session: (req as any).session,
        user: req.user,
        sessionID: (req as any).sessionID,
      });
    });

    // Setup passport serialization for mock user
    passport.serializeUser((user: Express.User, cb) => cb(null, user));
    passport.deserializeUser((user: Express.User, cb) => cb(null, user));

    return;
  }

  const config = await getOidcConfig();

  const verify: VerifyFunction = async (
    tokens: client.TokenEndpointResponse & client.TokenEndpointResponseHelpers,
    verified: passport.AuthenticateCallback
  ) => {
    const user = {};
    updateUserSession(user, tokens);
    const claims = tokens.claims();
    await upsertUser(claims);
    
    // Award "First Steps" badge on account creation (idempotent - safe to run on every login)
    // CRITICAL: Isolated try/catch ensures badge errors never block login
    // TODO (Production): Move to post-commit queue to prevent blocking login path
    if (claims?.sub) {
      try {
        await checkAndAwardBadges(claims.sub, ["create_account"]).catch((error) => {
          console.error("Error awarding create_account badge (non-blocking):", error);
        });
      } catch (error) {
        // Double isolation: catch both promise rejection and sync errors
        console.error("Error in badge awarding wrapper (non-blocking):", error);
      }
    }
    
    verified(null, user);
  };

  // Keep track of registered strategies
  const registeredStrategies = new Set<string>();

  // Helper function to ensure strategy exists for a domain
  const ensureStrategy = (domain: string) => {
    const strategyName = `replitauth:${domain}`;
    if (!registeredStrategies.has(strategyName)) {
      const strategy = new Strategy(
        {
          name: strategyName,
          config,
          scope: "openid email profile offline_access",
          callbackURL: `https://${domain}/api/callback`,
        },
        verify,
      );
      passport.use(strategy);
      registeredStrategies.add(strategyName);
    }
  };

  passport.serializeUser((user: Express.User, cb) => cb(null, user));
  passport.deserializeUser((user: Express.User, cb) => cb(null, user));

  app.get("/api/login", (req, res, next) => {
    ensureStrategy(req.hostname);
    passport.authenticate(`replitauth:${req.hostname}`, {
      prompt: "login consent",
      scope: ["openid", "email", "profile", "offline_access"],
    })(req, res, next);
  });

  app.get("/api/callback", (req, res, next) => {
    ensureStrategy(req.hostname);
    passport.authenticate(`replitauth:${req.hostname}`, {
      successReturnToOrRedirect: "/",
      failureRedirect: "/api/login",
    })(req, res, next);
  });

  app.get("/api/logout", (req, res) => {
    req.logout(() => {
      res.redirect(
        client.buildEndSessionUrl(config, {
          client_id: process.env.REPL_ID!,
          post_logout_redirect_uri: `${req.protocol}://${req.hostname}`,
        }).href
      );
    });
  });
}

export const isAuthenticated: RequestHandler = async (req, res, next) => {
  const user = req.user as any;

  if (!req.isAuthenticated() || !user.expires_at) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  const now = Math.floor(Date.now() / 1000);
  if (now <= user.expires_at) {
    return next();
  }

  const refreshToken = user.refresh_token;
  if (!refreshToken) {
    res.status(401).json({ message: "Unauthorized" });
    return;
  }

  try {
    const config = await getOidcConfig();
    const tokenResponse = await client.refreshTokenGrant(config, refreshToken);
    updateUserSession(user, tokenResponse);
    return next();
  } catch (error) {
    res.status(401).json({ message: "Unauthorized" });
    return;
  }
};
