import prisma from '../models/index.js';
import logger from '../utils/logger.js';

export const addRevokedToken = async (jti, expiresAt) => {
  logger.info('Revoking token with jti: %s', jti);
  await prisma.revokedToken.create({
    data: { jti, expiresAt },
  });
};

export const isTokenRevoked = async (jti) => {
  const token = await prisma.revokedToken.findUnique({ where: { jti } });
  if (token) logger.info('Token is revoked (jti: %s)', jti);
  return !!token;
};

export const cleanupExpiredRevokedTokens = async () => {
  const result = await prisma.revokedToken.deleteMany({
    where: { expiresAt: { lt: new Date() } },
  });
  if (result.count > 0) logger.info('Cleaned up %d expired revoked tokens', result.count);
};
