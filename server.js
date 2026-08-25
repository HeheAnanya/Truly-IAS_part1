const path = require("path");
const express = require("express");
const bcrypt = require("bcryptjs");
const store = require("./backend/store");
const otp = require("./backend/otp");
const auth = require("./backend/auth");

const app = express();

app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

function maskEmail(email) {
    const [name, domain] = email.split("@");
    if (!domain) return email;
    const visible = name.slice(0, 2);
    return `${visible}${"*".repeat(Math.max(name.length - 2, 1))}@${domain}`;
}

function maskMobile(mobile) {
    return mobile.replace(/\d(?=\d{2})/g, "*");
}
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
    otp.deliverOtpSimulated({ channel, destination, code, purpose, });
    return { challenge, code, };

}
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
        devOtp: code,
    });
});
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
        store.updateUser(user.id, { mobileVerified: true, mfaEnabled: true })
    }

    return res.json({ verified: true, mfaEnabled: true, next: "registration-complete" })
});

app.get(/^(?!\/api\/).*/, (req, res) => {
    res.sendFile(path.join(__dirname, "public", "index.html"));
});

// ---------------------------------------------------------------------------

const PORT = process.env.PORT || 3000;
if (require.main === module) {
    app.listen(PORT, () => {
        console.log(`SecureID (Part 1 — Registration) server running on http://localhost:${PORT}`);
    });
}

module.exports = app;
