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
  } finally {
    cleanupLock = false;
  }
};

export function startCleanupJobs() {
  cleanupInterval = setInterval(
    async () => {
      await cleanupExpiredRevokedTokens();
      await cleanupExpiredRefreshTokens();
    },
    60 * 60 * 1000
  );
}

export function stopCleanupJobs() {
  if (cleanupInterval) {
    clearInterval(cleanupInterval);
  }
}
