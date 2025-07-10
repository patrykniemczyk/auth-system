const prisma = require("../models");

exports.addRevokedToken = async (jti, expiresAt) => {
  await prisma.revokedToken.create({
    data: { jti, expiresAt },
  });
};

exports.isTokenRevoked = async (jti) => {
  const token = await prisma.revokedToken.findUnique({ where: { jti } });
  return !!token;
};

exports.cleanupExpiredRevokedTokens = async () => {
  await prisma.revokedToken.deleteMany({
    where: { expiresAt: { lt: new Date() } },
  });
};
