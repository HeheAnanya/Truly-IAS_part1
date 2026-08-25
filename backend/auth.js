function validatePassword(password) {
  const errors = [];
  if (!password || password.length < 8) errors.push("At least 8 characters");
  if (!/[A-Z]/.test(password || "")) errors.push("1 uppercase letter");
  if (!/[0-9]/.test(password || "")) errors.push("1 number");
  if (!/[^A-Za-z0-9]/.test(password || "")) errors.push("1 special character");
  return { valid: errors.length === 0, errors };
}

module.exports = {
  validatePassword,
};
