import { cleanupExpiredRevokedTokens } from '../services/revokedTokenService.js';
import prisma from '../models/index.js';
import logger from '../utils/logger.js';

// Clean up expired refresh tokens
const cleanupExpiredRefreshTokens = async () => {
  const result = await prisma.refreshToken.deleteMany({
    where: { expiresAt: { lt: new Date() } },
  });
  if (result.count > 0) logger.info('Cleaned up %d expired refresh tokens', result.count);
};

export function startCleanupJobs() {
  // Run every hour
  setInterval(
    async () => {
      await cleanupExpiredRevokedTokens();
      await cleanupExpiredRefreshTokens();
    },
    60 * 60 * 1000
  ); // 1 hour
}
