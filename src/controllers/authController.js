import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import ms from 'ms';
import prisma from '../models/index.js';
import { cleanupExpiredRevokedTokens } from '../services/revokedTokenService.js';
import logger from '../utils/logger.js';

// --- Helper: TTL Validation ---
const parseTokenTTL = (ttl) => {
  try {
    let milliseconds = ms(ttl);
    if (milliseconds === undefined) {
      // Support 'd' for days (e.g., '7d')
      const match = /^([0-9]+)d$/.exec(ttl);
      if (match) {
        milliseconds = parseInt(match[1], 10) * 24 * 60 * 60 * 1000;
      }
    }
    if (!milliseconds || milliseconds > 24 * 60 * 60 * 1000 * 31) {
      // Max 31 days
      throw new Error('Token TTL too long or invalid');
    }
    return milliseconds;
  } catch {
    throw new Error(`Invalid TTL format: ${ttl}`);
  }
};

const register = async (req, res, next) => {
  try {
    const { username, password } = req.body;
    logger.info('Registration attempt for username: %s', username);
    // Input validation is handled by middleware
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
  } catch (err) {
    next(err);
  }
};

// Clean up expired refresh tokens
const cleanupExpiredRefreshTokens = async () => {
  await prisma.refreshToken.deleteMany({
    where: { expiresAt: { lt: new Date() } },
  });
};

let cleanupLock = false;
const coordinatedCleanup = async () => {
  if (cleanupLock) return;
  cleanupLock = true;
  try {
    await cleanupExpiredRevokedTokens();
    await cleanupExpiredRefreshTokens();
  } finally {
    cleanupLock = false;
  }
};

const login = async (req, res, next) => {
  try {
    const { username, password } = req.body;
    logger.info('Login attempt for username: %s', username);
    const user = await prisma.user.findUnique({ where: { username } });
    if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
      logger.warn('Login failed for username: %s', username);
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    await coordinatedCleanup();
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
        expiresAt: new Date(Date.now() + parseTokenTTL(process.env.REFRESH_TOKEN_TTL)),
      },
    });
    logger.info('Login successful for username: %s', username);
    res.json({ accessToken, refreshToken });
  } catch (err) {
    logger.error('Login error:', err);
    next(err);
  }
};

const refresh = async (req, res, next) => {
  try {
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
    const jti = uuidv4();
    const accessToken = jwt.sign(
      { sub: user.id, username: user.username, role: user.role, jti },
      process.env.JWT_ACCESS_SECRET,
      { expiresIn: process.env.ACCESS_TOKEN_TTL }
    );
    logger.info('Refresh token successful for user: %s', user.username);
    res.json({ accessToken });
  } catch (err) {
    next(err);
  }
};

const logout = async (req, res, next) => {
  try {
    const { refreshToken } = req.body;
    logger.info('Logout attempt');
    if (!refreshToken) {
      logger.warn('Logout failed: no refresh token provided');
      return res.status(400).json({ error: 'Refresh token required' });
    }
    await prisma.refreshToken.deleteMany({ where: { token: refreshToken } });
    logger.info('Logout successful');
    res.json({ message: 'Logged out' });
  } catch (err) {
    next(err);
  }
};

export { register, login, refresh, logout, coordinatedCleanup };
