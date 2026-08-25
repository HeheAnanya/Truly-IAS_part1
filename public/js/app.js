async function api(path, method = "GET", body) {
    const res = await fetch(path, {
        method,
        headers: body ? { "Content-Type": "application/json" } : undefined,
        body: body ? JSON.stringify(body) : undefined,
    });
    const data = await res.json().catch(() => ({}));
    return { ok: res.status, data };
}
const screens = document.querySelectorAll(".screen");

function showScreen(name, { pushHistory = true } = {}) {
  const screen = document.querySelector(
    `[data-screen="${name}"]`
  );
  if (!screen) {
    console.error("Screen not found:", name);
    return;
  }
  screens.forEach((s) => {
    s.classList.toggle(
      "active",
      s.dataset.screen === name
    );
  });
  updateStepper(name);
  if (pushHistory) {
    history.pushState(
      { screen: name },
      "",
      `#${name}`
    );
  }
}
function updateStepper(screenName) {
  const stepper = document.getElementById("registration-stepper");

  if (!stepper) return;

  let currentStep = 1;
  if (screenName === "reg-details") {
    currentStep = 1;
  }
  else if (screenName === "otp") {
    if (otpState.channel === "sms") {
      currentStep = 3;
    } else {
      currentStep = 2;
    }
  }
  else if (
    screenName === "reg-mfa-complete"
  ) {
    currentStep = 4;
  }
  else if (
    screenName === "reg-success" ||
    screenName === "login-placeholder"
  ) {
    currentStep = 5;
  }

  const steps = stepper.querySelectorAll(".step");

  steps.forEach((step) => {
    const stepNumber = Number(step.dataset.step);

    step.classList.remove("active", "completed");

    if (stepNumber < currentStep) {
      step.classList.add("completed");
    }

    if (stepNumber === currentStep) {
      step.classList.add("active");
    }
  });
}
// ------------------------------------------------------------
// Initial screen
// ------------------------------------------------------------
const initialScreen =
  location.hash.replace("#", "") || "reg-details";

showScreen(initialScreen, {
  pushHistory: false
});


// ------------------------------------------------------------
// Browser Back / Forward
// ------------------------------------------------------------

window.addEventListener("popstate", (event) => {
  const screen =
    event.state?.screen ||
    location.hash.replace("#", "") ||
    "reg-details";

  showScreen(screen, {
    pushHistory: false
  });
});


document.querySelectorAll("[data-goto]").forEach((el) => {
  el.addEventListener("click", (e) => {
    e.preventDefault();
    const target = el.dataset.goto;
    if (target){
    showScreen(el.dataset.goto)}
  });
});



document.querySelectorAll("[data-goto-back]").forEach((el) => {
  el.addEventListener("click", (e) => {
    e.preventDefault();
    if (history.length>1){
    history.back();}
    else{
        showScreen("reg-details")
    }
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


const otpBoxes = Array.from(document.querySelectorAll("#otp-boxes input"));
let otpState = {
    challengeId: null,
    purpose: null, // 'register-email' | 'register-sms' | 'mfa-setup'
    userId: null,
    channel: null,
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

function renderOtpScreen({ purpose, challengeId, userId, channel, destination, ttlSeconds,pushHistory = true }) {
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
    showScreen("otp",{pushHistory});
    if (channel !== "totp") startOtpTimer(otpState.ttlSeconds);
}

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
    else {
    return;
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
        showScreen("reg-mfa-complete");
    } 
});

document.getElementById("otp-resend-link").addEventListener("click", async (e) => {
    e.preventDefault();
    if (e.currentTarget.classList.contains("disabled")) return;

    if (otpState.purpose === "register-email") {
        const { data } = await api("/api/send-email-otp", "POST", { userId: otpState.userId, purpose: "register-email" });
        renderOtpScreen({ purpose: "register-email", challengeId: data.challengeId, userId: otpState.userId, channel: "email", destination: data.maskedEmail, ttlSeconds: data.expiresInSeconds ,pushHistory:false});
    } else if (otpState.purpose === "register-sms") {
        const { data } = await api("/api/send-sms-otp", "POST", { userId: otpState.userId, purpose: "register-sms" });
        renderOtpScreen({ purpose: "register-sms", challengeId: data.challengeId, userId: otpState.userId, channel: "sms", destination: data.maskedMobile, ttlSeconds: data.expiresInSeconds });
    }
});


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
        pushHistory:false
    });
});

