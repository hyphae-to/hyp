const REDACTED = "[REDACTED]";
const JSON_PRIVATE_KEY = /("private_key"\s*:\s*)"(?:[^"\\]|\\[\s\S])*(?:"|\\?$)/gi;
const PRIVATE_KEY_PEM = /-----BEGIN ((?:[A-Z0-9]+ )*PRIVATE KEY)-----[\s\S]*?(?:-----END \1-----|$)/g;
const SECRET_PATTERNS = [
  /\b(?:xox[a-z]+-|xapp-)[A-Za-z0-9-]{12,}/g,
  /\b(?:ghp_|github_pat_)[A-Za-z0-9_]{20,}/g,
  /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g,
  /\bAIza[A-Za-z0-9_-]{35}(?![A-Za-z0-9_-])/g,
  /\bya29\.[A-Za-z0-9_-]{16,}/g,
  /\bsk-(?:(?:ant|proj)-)?[A-Za-z0-9_-]{16,}/g,
  /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g,
];

export function redactSlackSecrets(text) {
  let redacted = text.replace(JSON_PRIVATE_KEY, `$1"${REDACTED}"`).replace(PRIVATE_KEY_PEM, REDACTED);
  for (const pattern of SECRET_PATTERNS) {
    redacted = redacted.replace(pattern, REDACTED);
  }
  return redacted;
}

// Accepts the plugin's projected JSON data, including nested interaction fields.
export function redactSlackInboundData(data) {
  let removed = false;
  function redactValue(value, key) {
    if (key?.toLowerCase() === "private_key") {
      removed ||= value !== REDACTED;
      return REDACTED;
    }
    if (typeof value === "string") {
      const redacted = redactSlackSecrets(value);
      removed ||= redacted !== value;
      return redacted;
    }
    if (Array.isArray(value)) return value.map((item) => redactValue(item));
    if (value && typeof value === "object") {
      return Object.fromEntries(Object.entries(value).map(([name, item]) => [name, redactValue(item, name)]));
    }
    return value;
  }
  const redacted = redactValue(data);
  if (removed) redacted.secret_removed = true;
  return redacted;
}
