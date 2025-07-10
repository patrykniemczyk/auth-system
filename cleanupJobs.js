import { cleanupExpiredRevokedTokens } from './src/services/revokedTokenService.js';
import prisma from './src/models/index.js';

// Clean up expired refresh tokens
const cleanupExpiredRefreshTokens = async () => {
  await prisma.refreshToken.deleteMany({
    where: { expiresAt: { lt: new Date() } },
  });
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
