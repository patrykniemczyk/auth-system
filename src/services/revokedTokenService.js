import prisma from '../models/index.js';
import logger from '../utils/logger.js';

/**
 * Adds a revoked token (jti) to the database
 * @param {string} jti - JWT ID
 * @param {Date} expiresAt - Expiry date
 */
export const addRevokedToken = async (jti, expiresAt) => {
  logger.info('Revoking token with jti: %s', jti);
  await prisma.revokedToken.create({
    data: { jti, expiresAt },
  });
};

/**
 * Checks if a token (jti) is revoked
 * @param {string} jti - JWT ID
 * @returns {Promise<boolean>}
 */
export const isTokenRevoked = async (jti) => {
  const token = await prisma.revokedToken.findUnique({ where: { jti } });
  if (token) logger.info('Token is revoked (jti: %s)', jti);
  return !!token;
};

/**
 * Cleans up expired revoked tokens from the database
 */
export const cleanupExpiredRevokedTokens = async () => {
  const result = await prisma.revokedToken.deleteMany({
    where: { expiresAt: { lt: new Date() } },
  });
  if (result.count > 0) logger.info('Cleaned up %d expired revoked tokens', result.count);
};
