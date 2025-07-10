import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import ms from 'ms';
import prisma from '../models/index.js';
import { cleanupExpiredRevokedTokens } from '../services/revokedTokenService.js';
import logger from '../utils/logger.js';
import { auditLog } from '../utils/auditLogger.js';
import { getBcryptCost } from '../../server.js';

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

/**
 * Registers a new user
 * @param {import('express').Request} req
 * @param {import('express').Response} res
 * @param {import('express').NextFunction} next
 */
const register = async (req, res, next) => {
  try {
    const { username, password } = req.body;
    logger.info('Registration attempt for username: %s', username);
    // Input validation is handled by middleware
    const existing = await prisma.user.findUnique({ where: { username } });
    if (existing) {
      logger.warn('Registration failed: username already taken (%s)', username);
      auditLog('register_fail', { username, ip: req.ip });
      return res.status(409).json({ error: 'Username already taken' });
    }
    const bcryptCost = getBcryptCost();
    const passwordHash = await bcrypt.hash(password, bcryptCost);
    const user = await prisma.user.create({
      data: { username, passwordHash },
    });
    logger.info('User registered: %s', username);
    auditLog('register_success', { username, userId: user.id, ip: req.ip });
    res.status(201).json({ id: user.id, username: user.username });
  } catch (err) {
    logger.error('Register error:', err);
    auditLog('register_error', { error: err.message, ip: req.ip });
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

/**
 * Logs in a user and issues tokens
 * @param {import('express').Request} req
 * @param {import('express').Response} res
 * @param {import('express').NextFunction} next
 */
const login = async (req, res, next) => {
  try {
    const { username, password } = req.body;
    logger.info('Login attempt for username: %s', username);
    const user = await prisma.user.findUnique({ where: { username } });
    if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
      logger.warn('Login failed for username: %s', username);
      auditLog('login_fail', { username, ip: req.ip });
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
    auditLog('login_success', { username, userId: user.id, ip: req.ip });
    res.json({ accessToken, refreshToken });
  } catch (err) {
    logger.error('Login error:', err);
    auditLog('login_error', { error: err.message, ip: req.ip });
    next(err);
  }
};

/**
 * Rotates refresh token and issues new access token
 * @param {import('express').Request} req
 * @param {import('express').Response} res
 * @param {import('express').NextFunction} next
 */
const refresh = async (req, res, next) => {
  try {
    const { refreshToken } = req.body;
    logger.info('Refresh token attempt');
    if (!refreshToken) {
      logger.warn('Refresh failed: no refresh token provided');
      auditLog('refresh_fail', { ip: req.ip });
      return res.status(400).json({ error: 'Refresh token required' });
    }
    const tokenRecord = await prisma.refreshToken.findUnique({
      where: { token: refreshToken },
    });
    if (!tokenRecord || tokenRecord.expiresAt < new Date()) {
      if (tokenRecord) await prisma.refreshToken.delete({ where: { token: refreshToken } });
      logger.warn('Refresh failed: invalid or expired refresh token');
      auditLog('refresh_fail', { ip: req.ip });
      return res.status(401).json({ error: 'Invalid or expired refresh token' });
    }
    // Refresh token rotation: Invalidate old, issue new
    await prisma.refreshToken.delete({ where: { token: refreshToken } });
    const user = await prisma.user.findUnique({
      where: { id: tokenRecord.userId },
    });
    if (!user) {
      logger.warn('Refresh failed: user not found');
      auditLog('refresh_fail', { ip: req.ip });
      return res.status(401).json({ error: 'User not found' });
    }
    const jti = uuidv4();
    const accessToken = jwt.sign(
      { sub: user.id, username: user.username, role: user.role, jti },
      process.env.JWT_ACCESS_SECRET,
      { expiresIn: process.env.ACCESS_TOKEN_TTL }
    );
    // Issue new refresh token
    const newRefreshToken = uuidv4();
    await prisma.refreshToken.create({
      data: {
        token: newRefreshToken,
        userId: user.id,
        expiresAt: new Date(Date.now() + parseTokenTTL(process.env.REFRESH_TOKEN_TTL)),
      },
    });
    logger.info('Refresh token successful for user: %s', user.username);
    auditLog('refresh_success', { username: user.username, userId: user.id, ip: req.ip });
    res.json({ accessToken, refreshToken: newRefreshToken });
  } catch (err) {
    logger.error('Refresh error:', err);
    auditLog('refresh_error', { error: err.message, ip: req.ip });
    next(err);
  }
};

/**
 * Logs out a user by removing refresh token
 * @param {import('express').Request} req
 * @param {import('express').Response} res
 * @param {import('express').NextFunction} next
 */
const logout = async (req, res, next) => {
  try {
    const { refreshToken } = req.body;
    logger.info('Logout attempt');
    if (!refreshToken) {
      logger.warn('Logout failed: no refresh token provided');
      auditLog('logout_fail', { ip: req.ip });
      return res.status(400).json({ error: 'Refresh token required' });
    }
    await prisma.refreshToken.deleteMany({ where: { token: refreshToken } });
    logger.info('Logout successful');
    auditLog('logout_success', { ip: req.ip });
    res.json({ message: 'Logged out' });
  } catch (err) {
    logger.error('Logout error:', err);
    auditLog('logout_error', { error: err.message, ip: req.ip });
    next(err);
  }
};

export { register, login, refresh, logout, coordinatedCleanup };
