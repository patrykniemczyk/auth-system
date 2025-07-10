import { cleanupExpiredRevokedTokens } from '../services/revokedTokenService.js';
import prisma from '../models/index.js';
import logger from '../utils/logger.js';

let cleanupInterval;
let cleanupLock = false;

// Clean up expired refresh tokens
const cleanupExpiredRefreshTokens = async () => {
  if (cleanupLock) return;
  cleanupLock = true;
  try {
    const result = await prisma.refreshToken.deleteMany({
      where: { expiresAt: { lt: new Date() } },
    });
    if (result.count > 0) logger.info('Cleaned up %d expired refresh tokens', result.count);
  } catch (err) {
    logger.error('Error during refresh token cleanup:', err);
  } finally {
    cleanupLock = false;
  }
};

/**
 * Starts periodic cleanup jobs for expired tokens
 */
export function startCleanupJobs() {
  cleanupInterval = setInterval(
    async () => {
      await cleanupExpiredRevokedTokens();
      await cleanupExpiredRefreshTokens();
    },
    60 * 60 * 1000
  );
}

/**
 * Stops periodic cleanup jobs
 */
export function stopCleanupJobs() {
  if (cleanupInterval) {
    clearInterval(cleanupInterval);
  }
}
