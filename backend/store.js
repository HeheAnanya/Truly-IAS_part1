/**
 * In-memory "database" for Part 1 (Registration).
 *
 * This is intentionally NOT a real database — the assignment is about
 * demonstrating the IAM *flow*, not building a data layer. Everything here
 * lives in server memory and resets when the server restarts. When Part 2
 * (Login) is added, this same module keeps working unchanged — Login just
 * reads users that Registration already created here.
 */

const crypto = require("crypto");

const users = new Map(); // userId -> user object
const usersByEmail = new Map(); // lowercased email -> userId
const challenges = new Map(); // challengeId -> challenge object

function createUser({ fullName, email, mobile, passwordHash }) {
  const id = "usr_" + crypto.randomUUID();
  const user = {
    id,
    fullName,
    email: email.toLowerCase(),
    mobile,
    passwordHash,
    emailVerified: false,
    mobileVerified: false,
    mfaEnabled: false,
    mfaMethod: null, // 'email' | 'sms' | 'totp'
    totpSecret: null,
    pendingTotpSecret: null,
    mfaSetupAttempts: 0,
    createdAt: new Date().toISOString(),
  };
  users.set(id, user);
  usersByEmail.set(user.email, id);
  return user;
}

function getUserById(id) {
  return users.get(id) || null;
}

function getUserByEmail(email) {
  const id = usersByEmail.get(String(email).toLowerCase());
  return id ? users.get(id) : null;
}

function updateUser(id, patch) {
  const user = users.get(id);
  if (!user) return null;
  Object.assign(user, patch);
  return user;
}

function createChallenge({ userId, channel, purpose, otpHash, expiresAt, maxAttempts = 3 }) {
  const challengeId = "chg_" + crypto.randomUUID();
  const challenge = {
    challengeId,
    userId,
    channel, // 'email' | 'sms' | 'totp'
    purpose, // 'register-email' | 'register-sms' | 'mfa-setup'
    otpHash,
    expiresAt,
    attempts: 0,
    maxAttempts,
    consumed: false,
    createdAt: Date.now(),
  };
  challenges.set(challengeId, challenge);
  return challenge;
}

function getChallenge(challengeId) {
  return challenges.get(challengeId) || null;
}

module.exports = {
  createUser,
  getUserById,
  getUserByEmail,
  updateUser,
  createChallenge,
  getChallenge,
};
