import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import ms from 'ms';
import prisma from '../models/index.js';
import { addRevokedToken, cleanupExpiredRevokedTokens } from '../services/revokedTokenService.js';
import logger from '../utils/logger.js';

const register = async (req, res) => {
  const { username, password } = req.body;
  logger.info('Registration attempt for username: %s', username);
  if (!username || !password) {
    logger.warn('Registration failed: missing username or password');
    return res.status(400).json({ error: 'Username and password required' });
  }
  const existing = await prisma.user.findUnique({ where: { username } });
  if (existing) {
    logger.warn('Registration failed: username already taken (%s)', username);
    return res.status(409).json({ error: 'Username already taken' });
  }
  const passwordHash = await bcrypt.hash(password, 10);
  const user = await prisma.user.create({
    data: { username, passwordHash },
  });
  logger.info('User registered: %s', username);
  res.status(201).json({ id: user.id, username: user.username });
};

// Clean up expired refresh tokens
const cleanupExpiredRefreshTokens = async () => {
  await prisma.refreshToken.deleteMany({
    where: { expiresAt: { lt: new Date() } },
  });
};

const login = async (req, res) => {
  const { username, password } = req.body;
  logger.info('Login attempt for username: %s', username);
  const user = await prisma.user.findUnique({ where: { username } });
  if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
    logger.warn('Login failed for username: %s', username);
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  await cleanupExpiredRevokedTokens(); // Clean up expired revoked tokens on login
  await cleanupExpiredRefreshTokens(); // Clean up expired refresh tokens on login
  const jti = uuidv4();
  const accessToken = jwt.sign(
    { sub: user.id, username: user.username, role: user.role, jti },
    process.env.JWT_ACCESS_SECRET,
    { expiresIn: process.env.ACCESS_TOKEN_TTL }
  );
  const refreshToken = uuidv4();
  await prisma.refreshToken.create({
    data: {
      token: refreshToken,
      userId: user.id,
      expiresAt: new Date(Date.now() + ms(process.env.REFRESH_TOKEN_TTL)),
    },
  });
  logger.info('Login successful for username: %s', username);
  res.json({ accessToken, refreshToken });
};

const refresh = async (req, res) => {
  const { refreshToken } = req.body;
  logger.info('Refresh token attempt');
  if (!refreshToken) {
    logger.warn('Refresh failed: no refresh token provided');
    return res.status(400).json({ error: 'Refresh token required' });
  }
  const tokenRecord = await prisma.refreshToken.findUnique({
    where: { token: refreshToken },
  });
  if (!tokenRecord || tokenRecord.expiresAt < new Date()) {
    if (tokenRecord) await prisma.refreshToken.delete({ where: { token: refreshToken } });
    logger.warn('Refresh failed: invalid or expired refresh token');
    return res.status(401).json({ error: 'Invalid or expired refresh token' });
  }
  const user = await prisma.user.findUnique({
    where: { id: tokenRecord.userId },
  });
  if (!user) {
    logger.warn('Refresh failed: user not found');
    return res.status(401).json({ error: 'User not found' });
  }
  // Rotate refresh token
  await prisma.refreshToken.delete({ where: { token: refreshToken } });
  const newRefreshToken = uuidv4();
  await prisma.refreshToken.create({
    data: {
      token: newRefreshToken,
      userId: user.id,
      expiresAt: new Date(Date.now() + ms(process.env.REFRESH_TOKEN_TTL)),
    },
  });
  const jti = uuidv4();
  const accessToken = jwt.sign(
    { sub: user.id, username: user.username, role: user.role, jti },
    process.env.JWT_ACCESS_SECRET,
    { expiresIn: process.env.ACCESS_TOKEN_TTL }
  );
  await cleanupExpiredRefreshTokens(); // Clean up expired refresh tokens on refresh
  logger.info('Refresh token successful for user: %s', user.username);
  res.json({ accessToken, refreshToken: newRefreshToken });
};

const logout = async (req, res) => {
  const { refreshToken } = req.body;
  logger.info('Logout attempt');
  if (!refreshToken) {
    logger.warn('Logout failed: no refresh token provided');
    return res.status(400).json({ error: 'Refresh token required' });
  }
  // Remove refresh token
  await prisma.refreshToken.deleteMany({ where: { token: refreshToken } });
  // Revoke current access token if provided in Authorization header
  const authHeader = req.headers['authorization'];
  if (authHeader) {
    const token = authHeader.split(' ')[1];
    try {
      const payload = jwt.verify(token, process.env.JWT_ACCESS_SECRET);
      await addRevokedToken(payload.jti, new Date(Date.now() + ms(process.env.ACCESS_TOKEN_TTL)));
      logger.info('Access token revoked for jti: %s', payload.jti);
    } catch {
      logger.warn('Logout: invalid or missing access token');
    }
  }
  logger.info('Logout successful');
  res.json({ message: 'Logged out' });
};

export default {
  register,
  login,
  refresh,
  logout,
};
