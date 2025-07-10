import prisma from '../models/index.js';

export const addRevokedToken = async (jti, expiresAt) => {
  await prisma.revokedToken.create({
    data: { jti, expiresAt },
  });
};

export const isTokenRevoked = async (jti) => {
  const token = await prisma.revokedToken.findUnique({ where: { jti } });
  return !!token;
};

export const cleanupExpiredRevokedTokens = async () => {
  await prisma.revokedToken.deleteMany({
    where: { expiresAt: { lt: new Date() } },
  });
};
