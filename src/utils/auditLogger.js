import logger from './logger.js';

/**
 * Logs audit events for authentication actions
 * @param {string} event - Event type (e.g., 'login', 'register', 'refresh', 'logout')
 * @param {object} details - Additional details (user, IP, etc.)
 */
export function auditLog(event, details) {
  logger.info(`[AUDIT] ${event}`, details);
}
