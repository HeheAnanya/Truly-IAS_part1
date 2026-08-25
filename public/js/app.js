async function api(path, method="GET",body) {
  const res = await fetch(path, {
    method:method,
    headers: body ? { "Content-Type": "application/json" } : undefined,
    credentials: "include", // send/receive the session cookie
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await res.json().catch((err) => (console.log(err)));
  return { ok: res.status, data };
}

// In-memory only — deliberately never written to localStorage/sessionStorage.
let jwtToken = null;

const screens = document.querySelectorAll(".screen");
let screenHistory = [];

function showScreen(name, { pushHistory = true } = {}) {
  if (pushHistory && screenHistory[screenHistory.length - 1] !== name) {
    screenHistory.push(name);
  }
  screens.forEach((s) => s.classList.toggle("active", s.dataset.screen === name));
}

document.querySelectorAll("[data-goto]").forEach((el) => {
  el.addEventListener("click", (e) => {
    e.preventDefault();
    showScreen(el.dataset.goto);
  });
});

document.querySelectorAll("[data-goto-back]").forEach((el) => {
  el.addEventListener("click", (e) => {
    e.preventDefault();
    screenHistory.pop();
    const prev = screenHistory.pop() || "login-default";
    showScreen(prev);
  });
});

document.querySelectorAll("[data-toggle-password]").forEach((btn) => {
  btn.addEventListener("click", () => {
    const input = document.getElementById(btn.dataset.togglePassword);
    input.type = input.type === "password" ? "text" : "password";
    btn.textContent = input.type === "password" ? "👁" : "🙈";
  });
});

const regPasswordInput = document.getElementById("reg-password");
regPasswordInput.addEventListener("input", () => {
  const v = regPasswordInput.value;
  setRule("len", v.length >= 8);
  setRule("upper", /[A-Z]/.test(v));
  setRule("num", /[0-9]/.test(v));
  setRule("special", /[^A-Za-z0-9]/.test(v));
});
function setRule(rule, met) {
  document.querySelector(`#password li[data-rule="${rule}"]`).classList.toggle("met", met);
}

// ---------------------------------------------------------------------------
// Shared OTP screen state + rendering
// ---------------------------------------------------------------------------

const otpBoxes = Array.from(document.querySelectorAll("#otp-boxes input"));
let otpState = {
  challengeId: null,
  purpose: null, // 'register-email' | 'register-sms' | 'mfa-setup' | 'login'
  userId: null,
  timerInterval: null,
  resendInterval: null,
  ttlSeconds: 120,
};

function wireOtpBoxNavigation() {
  otpBoxes.forEach((box, i) => {
    box.addEventListener("input", () => {
      box.value = box.value.replace(/\D/g, "").slice(0, 1);
      box.classList.remove("error");
      if (box.value && i < otpBoxes.length - 1) otpBoxes[i + 1].focus();
    });
    box.addEventListener("keydown", (e) => {
      if (e.key === "Backspace" && !box.value && i > 0) otpBoxes[i - 1].focus();
    });
    box.addEventListener("paste", (e) => {
      e.preventDefault();
      const digits = (e.clipboardData.getData("text").match(/\d/g) || []).slice(0, otpBoxes.length);
      digits.forEach((d, idx) => { if (otpBoxes[idx]) otpBoxes[idx].value = d; });
      const next = otpBoxes[Math.min(digits.length, otpBoxes.length - 1)];
      next.focus();
    });
  });
}
wireOtpBoxNavigation();

function currentOtpCode() {
  return otpBoxes.map((b) => b.value).join("");
}
function clearOtpBoxes() {
  otpBoxes.forEach((b) => { b.value = ""; b.classList.remove("error"); });
  otpBoxes[0].focus();
}
function markOtpError() {
  otpBoxes.forEach((b) => b.classList.add("error"));
}

function startOtpTimer(seconds) {
  clearInterval(otpState.timerInterval);
  clearInterval(otpState.resendInterval);
  const timerEl = document.getElementById("otp-timer");
  const timerRow = document.getElementById("otp-timer-row");
  const resendLink = document.getElementById("otp-resend-link");
  const resendCooldownEl = document.getElementById("otp-resend-cooldown");

  let remaining = seconds;
  resendLink.classList.add("disabled");
  timerRow.style.display = "";

  otpState.timerInterval = setInterval(() => {
    remaining -= 1;
    if (remaining <= 0) {
      clearInterval(otpState.timerInterval);
      timerEl.textContent = "00:00";
      timerRow.textContent = "";
      document.getElementById("otp-error").textContent = "This code has expired.";
      return;
    }
    timerEl.textContent = formatMMSS(remaining);
  }, 1000);

  let resendRemaining = Math.min(25, seconds);
  resendCooldownEl.textContent = formatMMSS(resendRemaining);
  otpState.resendInterval = setInterval(() => {
    resendRemaining -= 1;
    if (resendRemaining <= 0) {
      clearInterval(otpState.resendInterval);
      resendLink.classList.remove("disabled");
      resendCooldownEl.textContent = "";
      return;
    }
    resendCooldownEl.textContent = formatMMSS(resendRemaining);
  }, 1000);
}

function formatMMSS(totalSeconds) {
  const m = Math.floor(totalSeconds / 60).toString().padStart(2, "0");
  const s = Math.floor(totalSeconds % 60).toString().padStart(2, "0");
  return `${m}:${s}`;
}

/** Configure and show the shared OTP screen. */
function renderOtpScreen({ purpose, challengeId, userId, channel, destination, ttlSeconds, screenName = "otp" }) {
  otpState.purpose = purpose;
  otpState.challengeId = challengeId;
  otpState.userId = userId;
  otpState.channel = channel;
  otpState.ttlSeconds = ttlSeconds || 120;

  const icon = channel === "sms" ? "📱" : channel === "totp" ? "🔑" : "✉️";
  const title = channel === "sms" ? "Verify your mobile" : channel === "totp" ? "Enter the 6-digit code" : "Verify your email";
  document.getElementById("otp-icon").textContent = icon;
  document.getElementById("otp-title").textContent = title;
  document.getElementById("otp-destination").textContent = destination || "";
  document.getElementById("otp-subtitle").style.display = channel === "totp" ? "none" : "";
  document.getElementById("otp-error").textContent = "";
  document.getElementById("otp-wrong-number").hidden = channel !== "sms";
  document.getElementById("otp-resend-link").style.display = channel === "totp" ? "none" : "";
  document.getElementById("otp-didnt-receive").style.display = channel === "totp" ? "none" : "";

  clearOtpBoxes();
  showScreen(screenName);
  if (channel !== "totp") startOtpTimer(otpState.ttlSeconds);
}

// Submit handler shared by every OTP step (email / sms / mfa-setup / login)
document.getElementById("form-otp").addEventListener("submit", async (e) => {
  e.preventDefault();
  const code = currentOtpCode();
  if (code.length !== 6) return;

  const errorEl = document.getElementById("otp-error");
  errorEl.textContent = "";

  let endpoint;
  let payload = { challengeId: otpState.challengeId, code };

  if (otpState.purpose === "register-email") endpoint = "/api/verify-email-otp";
  else if (otpState.purpose === "register-sms") endpoint = "/api/verify-sms-otp";
  else if (otpState.purpose === "mfa-setup") { endpoint = "/api/verify-mfa-setup"; payload = { userId: otpState.userId, code }; }
  else if (otpState.purpose === "login") {
    endpoint = "/api/verify-login-otp";
    payload.rememberMe = document.querySelector('input[name="rememberMe"]')?.checked || false;
  }

  const { data } = await api(endpoint, "POST", payload);

  if (!data.verified) {
    markOtpError();
    if (data.reason === "expired") errorEl.textContent = "This code has expired.";
    else if (data.reason === "max_attempts") errorEl.textContent = "Maximum attempts reached. Please request a new code.";
    else errorEl.textContent = `Incorrect code. Please try again. ${data.attemptsLeft != null ? `You have ${data.attemptsLeft} attempt(s) left.` : ""}`;
    return;
  }

  clearInterval(otpState.timerInterval);
  clearInterval(otpState.resendInterval);

  if (otpState.purpose === "register-email") {
    // Auto-advance to SMS OTP, per the guidelines' registration flow.
    const send = await api("/api/send-sms-otp", "POST", { userId: otpState.userId, purpose: "register-sms" });
    renderOtpScreen({
      purpose: "register-sms",
      challengeId: send.data.challengeId,
      userId: otpState.userId,
      channel: "sms",
      destination: send.data.maskedMobile,
      ttlSeconds: send.data.expiresInSeconds,
    });
  } else if (otpState.purpose === "register-sms") {
    showScreen("reg-mfa-setup");
  } else if (otpState.purpose === "mfa-setup") {
    showScreen("reg-success");
  } else if (otpState.purpose === "login") {
    await loadDashboard();
  }
});

document.getElementById("otp-resend-link").addEventListener("click", async (e) => {
  e.preventDefault();
  if (e.currentTarget.classList.contains("disabled")) return;

  if (otpState.purpose === "register-email") {
    const { data } = await api("/api/send-email-otp", "POST", { userId: otpState.userId, purpose: "register-email" });
    renderOtpScreen({ purpose: "register-email", challengeId: data.challengeId, userId: otpState.userId, channel: "email", destination: data.maskedEmail, ttlSeconds: data.expiresInSeconds });
  } else if (otpState.purpose === "register-sms") {
    const { data } = await api("/api/send-sms-otp", "POST", { userId: otpState.userId, purpose: "register-sms" });
    renderOtpScreen({ purpose: "register-sms", challengeId: data.challengeId, userId: otpState.userId, channel: "sms", destination: data.maskedMobile, ttlSeconds: data.expiresInSeconds });
  } else if (otpState.purpose === "login") {
    const { data } = await api("/api/send-login-otp", "POST", { userId: otpState.userId, method: otpState.channel });
    const destination = otpState.channel === "email" ? data.maskedEmail : data.maskedMobile;
    renderOtpScreen({ purpose: "login", challengeId: data.challengeId, userId: otpState.userId, channel: otpState.channel, destination, ttlSeconds: data.expiresInSeconds });
  }
});

// ---------------------------------------------------------------------------
// REGISTRATION: details form
// ---------------------------------------------------------------------------

document.getElementById("form-register").addEventListener("submit", async (e) => {
  e.preventDefault();
  const form = e.target;
  const errorEl = document.getElementById("register-error");
  errorEl.classList.remove("visible");

  const payload = {
    fullName: form.fullName.value.trim(),
    email: form.email.value.trim(),
    mobile: "+91 " + form.mobile.value.trim(),
    password: form.password.value,
    agreeTerms: form.agreeTerms.checked,
  };

  const { ok, data } = await api("/api/register", "POST", payload);
  if (ok >= 400) {
    errorEl.textContent = data.error || "Something went wrong. Please check your details.";
    errorEl.classList.add("visible");
    return;
  }

  renderOtpScreen({
    purpose: "register-email",
    challengeId: data.challengeId,
    userId: data.userId,
    channel: "email",
    destination: data.maskedEmail,
    ttlSeconds: data.expiresInSeconds,
    screenName: "otp",
  });
});

// ---------------------------------------------------------------------------
// REGISTRATION: MFA setup (choose method)
// ---------------------------------------------------------------------------

document.getElementById("form-mfa-setup").addEventListener("submit", async (e) => {
  e.preventDefault();
  const method = document.querySelector('input[name="mfaMethod"]:checked').value;
  const { data } = await api("/api/setup-mfa", "POST", { userId: otpState.userId, method });

  if (data.next === "success") {
    showScreen("reg-success");
  } else if (data.next === "verify-authenticator") {
    document.getElementById("qr-image").src = data.qrDataUrl;
    document.getElementById("secret-key").textContent = data.secretKey;
    showScreen("reg-mfa-qr");
    document.getElementById("mfa-qr-continue").onclick = () => {
      renderOtpScreen({
        purpose: "mfa-setup",
        challengeId: null,
        userId: otpState.userId,
        channel: "totp",
        destination: "",
        screenName: "otp",
      });
    };
  }
});

document.getElementById("show-secret-key").addEventListener("click", (e) => {
  e.preventDefault();
  document.getElementById("secret-key").hidden = false;
});

// ---------------------------------------------------------------------------
// LOGIN: default form
// ---------------------------------------------------------------------------

let loginState = { userId: null, availableMethods: [], defaultMethod: null };

document.getElementById("form-login").addEventListener("submit", async (e) => {
  e.preventDefault();
  const form = e.target;
  const errorEl = document.getElementById("login-error");
  errorEl.classList.remove("visible");

  const payload = {
    emailOrUsername: form.emailOrUsername.value.trim(),
    password: form.password.value,
  };

  const { ok, data } = await api("/api/login", "POST", payload);

  if (ok >= 400) {
    errorEl.textContent = data.error || "Invalid email or password. Please try again.";
    errorEl.classList.add("visible");
    return;
  }

  if (!data.mfaRequired) {
    await loadDashboard();
    return;
  }

  loginState.userId = data.userId;
  loginState.availableMethods = data.availableMethods;
  loginState.defaultMethod = data.method;
  loginState.challengeId = data.challengeId;

  renderMethodChoices();
  showScreen("login-choose-method");
});

function renderMethodChoices() {
  const container = document.getElementById("method-options");
  const labels = {
    email: ["✉️", "Email OTP", "Receive a code on your email"],
    sms: ["📱", "SMS OTP", "Receive a code on your mobile"],
    totp: ["🔑", "Authenticator App", "Use code from authenticator app"],
  };
  container.innerHTML = loginState.availableMethods
    .map((m, i) => {
      const [icon, title, desc] = labels[m];
      const checked = m === loginState.defaultMethod ? "checked" : "";
      return `<label class="mfa-option">
        <input type="radio" name="loginMethod" value="${m}" ${checked} />
        <span class="mfa-option-text"><strong>${icon} ${title}</strong><small>${desc}</small></span>
      </label>`;
    })
    .join("");
}

document.getElementById("form-choose-method").addEventListener("submit", async (e) => {
  e.preventDefault();
  const method = document.querySelector('input[name="loginMethod"]:checked').value;

  const { data } =
    method === loginState.defaultMethod
      ? { data: { challengeId: loginState.challengeId, method } }
      : await api("/api/send-login-otp", "POST", { userId: loginState.userId, method });

  const destination =
    method === "email" ? data.maskedEmail || "your email" :
    method === "sms" ? data.maskedMobile || "your mobile" :
    "your authenticator app";

  renderOtpScreen({
    purpose: "login",
    challengeId: data.challengeId,
    userId: loginState.userId,
    channel: method,
    destination,
    ttlSeconds: data.expiresInSeconds || 120,
  });
});

// ---------------------------------------------------------------------------
// DASHBOARD
// ---------------------------------------------------------------------------

async function loadDashboard() {
  const { data } = await api("/api/me");
  if (!data.user) { showScreen("login-default"); return; }
  document.getElementById("dash-name").textContent = data.user.fullName.split(" ")[0];
  document.getElementById("dash-email").textContent = data.user.email;
  document.getElementById("token-output").textContent = "";
  jwtToken = null;
  showScreen("dashboard");
}

document.getElementById("btn-get-token").addEventListener("click", async () => {
  const { ok, data } = await api("/api/token", "POST");
  const out = document.getElementById("token-output");
  if (ok >= 400) { out.textContent = "Not authenticated."; return; }
  jwtToken = data.token;
  out.textContent = `JWT (expires in ${data.expiresIn}):\n${data.token}`;
});

document.getElementById("btn-call-protected").addEventListener("click", async () => {
  const out = document.getElementById("token-output");
  if (!jwtToken) { out.textContent = "Get a JWT token first."; return; }
  const res = await fetch("/api/protected", { headers: { Authorization: `Bearer ${jwtToken}` } });
  const data = await res.json();
  out.textContent = `GET /api/protected -> ${res.status}\n${JSON.stringify(data, null, 2)}`;
});

document.getElementById("btn-logout").addEventListener("click", async () => {
  await api("/api/logout", "POST");
  jwtToken = null;
  screenHistory = [];
  document.getElementById("form-login").reset();
  showScreen("login-default");
});

// ---------------------------------------------------------------------------
// Boot: if a session cookie is already valid, skip straight to dashboard
// ---------------------------------------------------------------------------

(async function boot() {
  const { data } = await api("/api/me");
  if (data.user) {
    await loadDashboard();
  } else {
    showScreen("login-default");
  }
})();
