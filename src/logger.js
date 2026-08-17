/**
 * Structured logging module (file-first, TUI-safe)
 */

import { mkdirSync, appendFileSync, chmodSync, existsSync } from 'node:fs';
import { dirname, join } from 'node:path';

const LOG_LEVELS = ['debug', 'info', 'warn', 'error'];
let currentLevel = process.env.LOG_LEVEL || 'info';
let quietMode = false;

const LOG_TO_CONSOLE = String(process.env.PI_LINEAR_TOOLS_LOG_TO_CONSOLE || '').toLowerCase() === 'true';
const DEFAULT_LOG_FILE = process.env.PI_LINEAR_TOOLS_LOG_FILE
  || join(process.env.HOME || process.cwd(), '.config', 'pi-linear-tools', 'pi-linear-tools.log');

let logFileReady = false;
let logFilePath = DEFAULT_LOG_FILE;

function ensureLogFileReady() {
  if (logFileReady) return;
  try {
    // Log lines may contain request metadata; keep the file private to the user.
    mkdirSync(dirname(logFilePath), { recursive: true, mode: 0o700 });
  } catch {
    // ignore; fallback handled in writeLogLine
  }
  if (process.platform !== 'win32' && existsSync(logFilePath)) {
    // Tighten permissions on log files created by earlier versions (default umask, typically 0644).
    try {
      chmodSync(logFilePath, 0o600);
    } catch {
      // best-effort
    }
  }
  logFileReady = true;
}

function writeLogLine(line, isError = false) {
  try {
    ensureLogFileReady();
    appendFileSync(logFilePath, `${line}\n`, { encoding: 'utf8', mode: 0o600 });
  } catch {
    // Last-resort fallback is disabled by default to protect TUI.
    // Only print when explicitly opted in.
    if (LOG_TO_CONSOLE) {
      if (isError) console.error(line);
      else console.log(line);
    }
  }

  if (LOG_TO_CONSOLE) {
    if (isError) console.error(line);
    else console.log(line);
  }
}

/**
 * Enable quiet mode (suppress info/debug/warn, keep only errors)
 */
export function setQuietMode(quiet) {
  quietMode = quiet;
}

/**
 * Check if a log level should be displayed
 */
function shouldLog(level) {
  if (quietMode && level !== 'error') return false;
  const currentIndex = LOG_LEVELS.indexOf(currentLevel);
  const levelIndex = LOG_LEVELS.indexOf(level);
  return levelIndex >= currentIndex;
}

/**
 * Format timestamp
 */
function getTimestamp() {
  return new Date().toISOString();
}

const MASKED = '***masked***';

// Keys whose string values are always redacted.
const SENSITIVE_KEY_PATTERN = /(api[-_]?key|access[-_]?token|refresh[-_]?token|id[-_]?token|secret|password|passwd|authorization|credential|^token$|^tokens$|^apikey$|^key$)/i;

// Keys that merely describe tokens (booleans/type labels), never the value itself.
const SAFE_KEY_PATTERN = /^(has[A-Z_].*|.*Length|.*Count|tokenType|token_type|tokenTypeHint|hasTokenHint|expiresAt|expiresIn|expires_in|scope|scopes)$/;

// Substrings that look like Linear credentials, regardless of key name (also inside messages/stacks).
const SENSITIVE_VALUE_PATTERN = /(?:Bearer\s+)?(?:lin_api_|lin_oauth_)[A-Za-z0-9_-]{8,}/g;

function scrubString(value) {
  return value.replace(SENSITIVE_VALUE_PATTERN, MASKED);
}

/**
 * Mask sensitive values in logs
 */
function maskValue(key, value) {
  const keyName = String(key || '');
  if (typeof value === 'string') {
    value = scrubString(value);
  }
  if (SAFE_KEY_PATTERN.test(keyName)) {
    return value;
  }
  if (SENSITIVE_KEY_PATTERN.test(keyName)) {
    if (value === null || value === undefined || typeof value === 'boolean' || typeof value === 'number') {
      return value;
    }
    return MASKED;
  }
  return value;
}

/**
 * Recursively redact sensitive values from a log payload.
 * Depth-limited to keep pathological payloads cheap.
 */
function redact(value, depth = 0) {
  if (typeof value === 'string') {
    return scrubString(value);
  }
  if (depth > 4 || value === null || typeof value !== 'object') {
    return value;
  }
  if (Array.isArray(value)) {
    return value.map((item) => redact(item, depth + 1));
  }
  if (value instanceof Error) {
    return {
      name: value.name,
      message: scrubString(String(value.message || '')),
      stack: typeof value.stack === 'string' ? scrubString(value.stack) : undefined,
    };
  }
  const out = {};
  for (const [key, entry] of Object.entries(value)) {
    const masked = maskValue(key, entry);
    out[key] = masked === MASKED ? MASKED : redact(masked, depth + 1);
  }
  return out;
}

/**
 * Format log entry
 */
function formatLog(level, message, data = {}) {
  const timestamp = getTimestamp();
  const entry = {
    timestamp,
    level: level.toUpperCase(),
    message: typeof message === 'string' ? scrubString(message) : message,
    ...redact(data && typeof data === 'object' ? data : {}),
  };
  return JSON.stringify(entry);
}

/**
 * Log at debug level
 */
export function debug(message, data = {}) {
  if (shouldLog('debug')) {
    writeLogLine(formatLog('debug', message, data));
  }
}

/**
 * Log at info level
 */
export function info(message, data = {}) {
  if (shouldLog('info')) {
    writeLogLine(formatLog('info', message, data));
  }
}

/**
 * Log at warn level
 */
export function warn(message, data = {}) {
  if (shouldLog('warn')) {
    writeLogLine(formatLog('warn', message, data));
  }
}

/**
 * Log at error level
 */
export function error(message, data = {}) {
  if (shouldLog('error')) {
    writeLogLine(formatLog('error', message, data), true);
  }
}

/**
 * Print startup banner
 */
export function printBanner() {
  info('pi-linear-tools startup');
}

/**
 * Log configuration summary (with secrets masked)
 */
export function logConfig(config) {
  info('Configuration loaded', {
    ...Object.fromEntries(
      Object.entries(config).map(([key, value]) => [key, maskValue(key, value)]),
    ),
  });
}

/**
 * Set log level
 */
export function setLogLevel(level) {
  if (LOG_LEVELS.includes(level)) {
    currentLevel = level;
    info(`Log level set to: ${level}`);
  } else {
    warn(`Invalid log level: ${level}. Using: ${currentLevel}`);
  }
}

/**
 * Expose active log file path for diagnostics/tests
 */
export function getLogFilePath() {
  return logFilePath;
}
