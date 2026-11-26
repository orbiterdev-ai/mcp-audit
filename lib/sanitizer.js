/**
 * 4-Layer Public & Report Sanitizer for MCP Audit.
 * Ensures zero private credentials, local filesystem paths, LAN IPs, or device serials
 * ever appear in audit reports or telemetry.
 */

const PATH_REGEX = /(?:[a-zA-Z]:[\\/]|(?:\/Users\/|\/home\/))[^\s'",:;]+/g;
const SECRET_REGEX = /\b(?:sk-[a-zA-Z0-9_-]{20,}|ghp_[a-zA-Z0-9_]{36,}|sbp_[a-f0-9]{40}|AKIA[0-9A-Z]{16}|bearer\s+[a-zA-Z0-9_.-]{20,})\b/gi;
const IP_REGEX = /\b(?:192\.168\.\d{1,3}\.\d{1,3}|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|100\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.0\.2\.\d{1,3}|198\.51\.100\.\d{1,3})\b/g;
const SERIAL_REGEX = /\b(?:emulator-\d{4,5}|(?=[A-Z0-9]*[A-Z])(?=[A-Z0-9]*[0-9])[A-Z0-9]{8,18})\b/g;

function sanitizeText(text) {
  if (typeof text !== 'string') {
    return text;
  }
  return text
    .replace(SECRET_REGEX, (match) => match.slice(0, 4) + '****' + match.slice(-4))
    .replace(PATH_REGEX, (match) => {
      const normalized = match.replace(/\\/g, '/');
      const parts = normalized.split('/');
      const last = parts[parts.length - 1];
      return `~/${last}`;
    })
    .replace(IP_REGEX, '<LAN_IP_REDACTED>')
    .replace(SERIAL_REGEX, '<DEVICE_SERIAL_REDACTED>');
}

function sanitizeObject(obj) {
  if (!obj || typeof obj !== 'object') {
    return sanitizeText(obj);
  }
  if (Array.isArray(obj)) {
    return obj.map(sanitizeObject);
  }
  const result = {};
  for (const [key, value] of Object.entries(obj)) {
    result[key] = sanitizeObject(value);
  }
  return result;
}

module.exports = {
  sanitizeText,
  sanitizeObject,
};
