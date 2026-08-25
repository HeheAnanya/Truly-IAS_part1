/**
 * SecureID — IAM Registration & Login journey.
 *
 * Everything security-relevant (password hashing, OTP generation/checking,
 * MFA, session creation, JWT issuing/validation) happens ONLY in this file
 * and lib/*.js — never in the browser. The frontend (public/) is purely
 * presentational: it calls these APIs and renders whatever screen the
 * response tells it to show.
 */

const path = require("path");
const express = require("express");
const session = require("express-session");
const cookieParser = require("cookie-parser");
const bcrypt = require("bcryptjs");
const { authenticator } = require("otplib");
const QRCode = require("qrcode");

const store = require("./lib/store");
const otp = require("./lib/otp");
const auth = require("./lib/auth");

const app = express();
const isProd = process.env.NODE_ENV === "production";

app.set("trust proxy", 1); // needed so `Secure` cookies work correctly behind Vercel's proxy
app.use(express.json());
app.use(cookieParser());

app.use(
  session({
    name: "sid",
    secret: process.env.SESSION_SECRET || "dev-session-secret-change-me",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true, // JS on the page can never read this cookie
      secure: isProd, // HTTPS-only in production (Vercel serves over HTTPS)
      sameSite: "lax", // CSRF mitigation while still allowing top-level navigation
      maxAge: 24 * 60 * 60 * 1000, // 1 day default; extended below for "remember me"
    },
  })
);

app.use(express.static(path.join(__dirname, "public")));

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function publicUser(user) {
  return {
    id: user.id,
    fullName: user.fullName,
    email: user.email,
    mobile: user.mobile,
    emailVerified: user.emailVerified,
    mobileVerified: user.mobileVerified,
    mfaEnabled: user.mfaEnabled,
    mfaMethod: user.mfaMethod,
  };
}

function maskEmail(email) {
  const [name, domain] = email.split("@");
  if (!domain) return email;
  const visible = name.slice(0, 2);
  return `${visible}${"*".repeat(Math.max(name.length - 2, 1))}@${domain}`;
}

function maskMobile(mobile) {
  return mobile.replace(/\d(?=\d{2})/g, "*");
}

/** Create + store + "deliver" an OTP challenge for email or sms. */
function issueOtpChallenge({ userId, channel, purpose, destination }) {
  const code = otp.generateOtp();
  const challenge = store.createChallenge({
    userId,
    channel,
    purpose,
    otpHash: otp.hashOtp(code),
    expiresAt: otp.otpExpiryTimestamp(),
    maxAttempts: otp.OTP_MAX_ATTEMPTS,
  });
  otp.deliverOtpSimulated({ channel, destination, code, purpose });
  return challenge;
}

// ---------------------------------------------------------------------------
// 1. REGISTRATION
// ---------------------------------------------------------------------------

app.post("/api/register", (req, res) => {
  const { fullName, email, mobile, password, agreeTerms } = req.body || {};

  if (!fullName || !email || !mobile || !password) {
    return res.status(400).json({ error: "All fields are required." });
  }
  if (!agreeTerms) {
    return res.status(400).json({ error: "You must agree to the Terms & Conditions." });
  }
  if (!/^\S+@\S+\.\S+$/.test(email)) {
    return res.status(400).json({ error: "Enter a valid email address." });
  }
  if (store.getUserByEmail(email)) {
    return res.status(409).json({ error: "An account with this email already exists." });
  }

  const { valid, errors } = auth.validatePassword(password);
  if (!valid) {
    return res.status(400).json({ error: "Password does not meet requirements.", details: errors });
  }

  const passwordHash = bcrypt.hashSync(password, 10);
  const user = store.createUser({ fullName, email, mobile, passwordHash });

  const challenge = issueOtpChallenge({
    userId: user.id,
    channel: "email",
    purpose: "register-email",
    destination: user.email,
  });

  return res.status(201).json({
    userId: user.id,
    challengeId: challenge.challengeId,
    maskedEmail: maskEmail(user.email),
    expiresInSeconds: otp.OTP_TTL_MS / 1000,
  });
});

// ---------------------------------------------------------------------------
// 2. EMAIL OTP  (registration)
// ---------------------------------------------------------------------------

app.post("/api/send-email-otp", (req, res) => {
  const { userId, purpose = "register-email" } = req.body || {};
  const user = store.getUserById(userId);
  if (!user) return res.status(404).json({ error: "User not found." });

  const challenge = issueOtpChallenge({
    userId: user.id,
    channel: "email",
    purpose,
    destination: user.email,
  });

  return res.json({
    challengeId: challenge.challengeId,
    maskedEmail: maskEmail(user.email),
    expiresInSeconds: otp.OTP_TTL_MS / 1000,
  });
});

app.post("/api/verify-email-otp", (req, res) => {
  const { challengeId, code } = req.body || {};
  const challenge = store.getChallenge(challengeId);
  const result = otp.verifyChallenge(challenge, code);

  if (!result.ok) {
    return res.status(400).json({ verified: false, reason: result.reason, attemptsLeft: result.attemptsLeft });
  }

  const user = store.getUserById(challenge.userId);
  if (challenge.purpose === "register-email") {
    store.updateUser(user.id, { emailVerified: true });
  }

  return res.json({ verified: true, next: "sms-otp" });
});

// ---------------------------------------------------------------------------
// 3. SMS OTP (registration)
// ---------------------------------------------------------------------------

app.post("/api/send-sms-otp", (req, res) => {
  const { userId, purpose = "register-sms" } = req.body || {};
  const user = store.getUserById(userId);
  if (!user) return res.status(404).json({ error: "User not found." });

  const challenge = issueOtpChallenge({
    userId: user.id,
    channel: "sms",
    purpose,
    destination: user.mobile,
  });

  return res.json({
    challengeId: challenge.challengeId,
    maskedMobile: maskMobile(user.mobile),
    expiresInSeconds: otp.OTP_TTL_MS / 1000,
  });
});

app.post("/api/verify-sms-otp", (req, res) => {
  const { challengeId, code } = req.body || {};
  const challenge = store.getChallenge(challengeId);
  const result = otp.verifyChallenge(challenge, code);

  if (!result.ok) {
    return res.status(400).json({ verified: false, reason: result.reason, attemptsLeft: result.attemptsLeft });
  }

  const user = store.getUserById(challenge.userId);
  if (challenge.purpose === "register-sms") {
    // Per the guidelines: successful SMS verification marks MFA as enabled.
    // Default the 2nd factor to email; the MFA-setup screen lets the user
    // upgrade this to an authenticator app before finishing registration.
    store.updateUser(user.id, { mobileVerified: true, mfaEnabled: true, mfaMethod: user.mfaMethod || "email" });
  }

  return res.json({ verified: true, next: "mfa-setup" });
});

// ---------------------------------------------------------------------------
// 4/5/6. MFA SETUP (choose method -> optional QR -> verify)
// ---------------------------------------------------------------------------

app.post("/api/setup-mfa", async (req, res) => {
  const { userId, method } = req.body || {};
  const user = store.getUserById(userId);
  if (!user) return res.status(404).json({ error: "User not found." });
  if (!["email", "sms", "totp"].includes(method)) {
    return res.status(400).json({ error: "Invalid MFA method." });
  }

  if (method === "email" || method === "sms") {
    // Both channels were already proven during registration, so no extra
    // verification step is needed — just record the preference.
    store.updateUser(user.id, { mfaMethod: method });
    return res.json({ next: "success" });
  }

  // method === 'totp' — generate a secret and QR code, but DON'T mark it
  // active until the user proves they can generate a valid code from it.
  const secret = authenticator.generateSecret();
  store.updateUser(user.id, { pendingTotpSecret: secret });
  const otpauthUrl = authenticator.keyuri(user.email, "SecureID", secret);
  const qrDataUrl = await QRCode.toDataURL(otpauthUrl);

  return res.json({ next: "verify-authenticator", qrDataUrl, secretKey: secret });
});

app.post("/api/verify-mfa-setup", (req, res) => {
  const { userId, code } = req.body || {};
  const user = store.getUserById(userId);
  if (!user || !user.pendingTotpSecret) {
    return res.status(400).json({ verified: false, reason: "no_pending_setup" });
  }

  user.mfaSetupAttempts = (user.mfaSetupAttempts || 0) + 1;
  if (user.mfaSetupAttempts > otp.OTP_MAX_ATTEMPTS) {
    return res.status(400).json({ verified: false, reason: "max_attempts" });
  }

  const isValid = authenticator.check(String(code), user.pendingTotpSecret);
  if (!isValid) {
    return res.status(400).json({
      verified: false,
      reason: "invalid",
      attemptsLeft: otp.OTP_MAX_ATTEMPTS - user.mfaSetupAttempts,
    });
  }

  store.updateUser(user.id, {
    mfaMethod: "totp",
    totpSecret: user.pendingTotpSecret,
    pendingTotpSecret: null,
    mfaSetupAttempts: 0,
  });

  return res.json({ verified: true, next: "success" });
});

// ---------------------------------------------------------------------------
// LOGIN
// ---------------------------------------------------------------------------

app.post("/api/login", (req, res) => {
  const { emailOrUsername, password } = req.body || {};
  const user = store.getUserByEmail(emailOrUsername || "");

  // Deliberately generic error so we don't reveal whether the email exists.
  const invalid = () => res.status(401).json({ error: "Invalid email or password. Please try again." });

  if (!user) return invalid();

  if (auth.isLockedOut(user)) {
    const retryInSeconds = Math.ceil((user.lockoutUntil - Date.now()) / 1000);
    return res.status(423).json({ error: "Account temporarily locked. Try again shortly.", retryInSeconds });
  }

  const passwordOk = bcrypt.compareSync(password || "", user.passwordHash);
  if (!passwordOk) {
    auth.registerFailedLogin(user);
    return invalid();
  }

  auth.resetLoginAttempts(user);

  if (!user.mfaEnabled) {
    // Shouldn't normally happen since registration always enables MFA, but
    // handled for completeness.
    req.session.userId = user.id;
    return res.json({ mfaRequired: false, user: publicUser(user) });
  }

  const method = user.mfaMethod || "email";
  const challenge = createLoginChallenge(user, method);

  const availableMethods = ["email", "sms"];
  if (user.totpSecret) availableMethods.push("totp");

  return res.json({
    mfaRequired: true,
    method,
    challengeId: challenge.challengeId,
    userId: user.id,
    availableMethods,
  });
});

function createLoginChallenge(user, method) {
  if (method === "totp") {
    // No OTP to generate/deliver — the code lives in the user's authenticator
    // app. We still print the currently-valid code to the console so the
    // flow is testable end-to-end without a real authenticator app.
    const currentCode = authenticator.generate(user.totpSecret);
    otp.deliverOtpSimulated({ channel: "totp", destination: user.email, code: currentCode, purpose: "login" });
    return store.createChallenge({
      userId: user.id,
      channel: "totp",
      purpose: "login",
      otpHash: null,
      expiresAt: Date.now() + 30 * 1000,
      maxAttempts: otp.OTP_MAX_ATTEMPTS,
    });
  }
  const destination = method === "email" ? user.email : user.mobile;
  return issueOtpChallenge({ userId: user.id, channel: method, purpose: "login", destination });
}

// Lets the "Choose a method" screen switch channels before verifying.
app.post("/api/send-login-otp", (req, res) => {
  const { userId, method } = req.body || {};
  const user = store.getUserById(userId);
  if (!user) return res.status(404).json({ error: "User not found." });
  if (method === "totp" && !user.totpSecret) {
    return res.status(400).json({ error: "Authenticator app is not set up on this account." });
  }
  const challenge = createLoginChallenge(user, method);
  return res.json({
    method,
    challengeId: challenge.challengeId,
    maskedEmail: maskEmail(user.email),
    maskedMobile: maskMobile(user.mobile),
    expiresInSeconds: method === "totp" ? 30 : otp.OTP_TTL_MS / 1000,
  });
});

app.post("/api/verify-login-otp", (req, res) => {
  const { challengeId, code, rememberMe } = req.body || {};
  const challenge = store.getChallenge(challengeId);
  if (!challenge) return res.status(400).json({ verified: false, reason: "not_found" });

  const user = store.getUserById(challenge.userId);

  let result;
  if (challenge.channel === "totp") {
    if (challenge.consumed) {
      result = { ok: false, reason: "consumed" };
    } else if (Date.now() > challenge.expiresAt) {
      result = { ok: false, reason: "expired" };
    } else {
      challenge.attempts += 1;
      const isValid = authenticator.check(String(code), user.totpSecret);
      if (isValid) {
        challenge.consumed = true;
        result = { ok: true };
      } else if (challenge.attempts >= challenge.maxAttempts) {
        result = { ok: false, reason: "max_attempts" };
      } else {
        result = { ok: false, reason: "invalid", attemptsLeft: challenge.maxAttempts - challenge.attempts };
      }
    }
  } else {
    result = otp.verifyChallenge(challenge, code);
  }

  if (!result.ok) {
    return res.status(400).json({ verified: false, reason: result.reason, attemptsLeft: result.attemptsLeft });
  }

  // Create the authenticated session.
  req.session.userId = user.id;
  if (rememberMe) {
    req.session.cookie.maxAge = 30 * 24 * 60 * 60 * 1000; // 30 days
  }

  return res.json({ verified: true, user: publicUser(user) });
});

// ---------------------------------------------------------------------------
// SESSION-BASED AUTH
// ---------------------------------------------------------------------------

app.get("/api/me", auth.requireSession, (req, res) => {
  const user = store.getUserById(req.session.userId);
  if (!user) return res.status(401).json({ error: "Not authenticated" });
  return res.json({ user: publicUser(user) });
});

app.post("/api/logout", (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("sid");
    res.json({ loggedOut: true });
  });
});

// ---------------------------------------------------------------------------
// JWT-BASED AUTH (separate protected API flow)
// ---------------------------------------------------------------------------

app.post("/api/token", auth.requireSession, (req, res) => {
  const user = store.getUserById(req.session.userId);
  if (!user) return res.status(401).json({ error: "Not authenticated" });
  const token = auth.issueJwt(user);
  return res.json({ token, tokenType: "Bearer", expiresIn: "5m" });
});

app.get("/api/protected", auth.requireJwt, (req, res) => {
  const user = store.getUserById(req.jwtPayload.sub);
  return res.json({
    message: "You reached a JWT-protected resource.",
    tokenSubject: req.jwtPayload.sub,
    user: user ? publicUser(user) : null,
  });
});

// ---------------------------------------------------------------------------
// Fallback: serve the SPA shell for any non-API GET route
// ---------------------------------------------------------------------------

app.get(/^(?!\/api\/).*/, (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// ---------------------------------------------------------------------------

const PORT = process.env.PORT || 3000;
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`SecureID IAM server running on http://localhost:${PORT}`);
  });
}

module.exports = app;
