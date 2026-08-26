const crypto = require("crypto");

const users = new Map();
const usersByEmail = new Map();
const challenges = new Map();

const redisUrl = String(process.env.UPSTASH_REDIS_REST_URL || "").replace(/\/$/, "");
const redisToken = process.env.UPSTASH_REDIS_REST_TOKEN || "";
const useRedis = Boolean(redisUrl && redisToken);

async function redisCommand(command, args = []) {
  if (!useRedis) return null;

  const response = await fetch(redisUrl, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${redisToken}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify([command, ...args]),
  });

  if (!response.ok) {
    const text = await response.text().catch(() => "");
    throw new Error(`Redis request failed (${response.status}): ${text}`);
  }

  const payload = await response.json();
  if (payload.error) throw new Error(`Redis command failed: ${payload.error}`);
  return payload.result;
}

function userKey(id) {
  return `secureid:user:${id}`;
}

function emailKey(email) {
  return `secureid:email:${String(email).toLowerCase()}`;
}

function challengeKey(id) {
  return `secureid:challenge:${id}`;
}

function secondsUntil(timestamp) {
  return Math.max(1, Math.ceil((Number(timestamp) - Date.now()) / 1000));
}

async function createUser({ fullName, email, mobile, passwordHash }) {
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
    mfaMethod: null,
    totpSecret: null,
    pendingTotpSecret: null,
    mfaSetupAttempts: 0,
    createdAt: new Date().toISOString(),
  };

  if (!useRedis) {
    users.set(id, user);
    usersByEmail.set(user.email, id);
    return user;
  }

  const existingId = await redisCommand("GET", [emailKey(user.email)]);
  if (existingId) {
    const error = new Error("EMAIL_EXISTS");
    error.code = "EMAIL_EXISTS";
    throw error;
  }

  await redisCommand("SET", [userKey(id), JSON.stringify(user)]);
  await redisCommand("SET", [emailKey(user.email), id]);
  return user;
}

async function getUserById(id) {
  if (!id) return null;

  if (!useRedis) return users.get(id) || null;

  const raw = await redisCommand("GET", [userKey(id)]);
  return raw ? JSON.parse(raw) : null;
}

async function getUserByEmail(email) {
  const normalizedEmail = String(email || "").toLowerCase();
  if (!normalizedEmail) return null;

  if (!useRedis) {
    const id = usersByEmail.get(normalizedEmail);
    return id ? users.get(id) || null : null;
  }

  const id = await redisCommand("GET", [emailKey(normalizedEmail)]);
  return id ? getUserById(id) : null;
}

async function updateUser(id, patch) {
  const user = await getUserById(id);
  if (!user) return null;

  Object.assign(user, patch);

  if (!useRedis) {
    users.set(id, user);
    return user;
  }

  await redisCommand("SET", [userKey(id), JSON.stringify(user)]);
  return user;
}

async function createChallenge({ userId, channel, purpose, otpHash, expiresAt, maxAttempts = 3 }) {
  const challengeId = "chg_" + crypto.randomUUID();
  const challenge = {
    challengeId,
    userId,
    channel,
    purpose,
    otpHash,
    expiresAt,
    attempts: 0,
    maxAttempts,
    consumed: false,
    createdAt: Date.now(),
  };

  if (!useRedis) {
    challenges.set(challengeId, challenge);
    return challenge;
  }

  await redisCommand("SET", [
    challengeKey(challengeId),
    JSON.stringify(challenge),
    "EX",
    secondsUntil(expiresAt),
  ]);

  return challenge;
}

async function getChallenge(challengeId) {
  if (!challengeId) return null;

  if (!useRedis) return challenges.get(challengeId) || null;

  const raw = await redisCommand("GET", [challengeKey(challengeId)]);
  return raw ? JSON.parse(raw) : null;
}

async function saveChallenge(challenge) {
  if (!challenge || !challenge.challengeId) return null;

  if (!useRedis) {
    challenges.set(challenge.challengeId, challenge);
    return challenge;
  }

  await redisCommand("SET", [
    challengeKey(challenge.challengeId),
    JSON.stringify(challenge),
    "EX",
    secondsUntil(challenge.expiresAt),
  ]);

  return challenge;
}

module.exports = {
  get usingRedis() {
    return useRedis;
  },
  createUser,
  getUserById,
  getUserByEmail,
  updateUser,
  createChallenge,
  getChallenge,
  saveChallenge,
};
