import jwt from 'jsonwebtoken';
import { isTokenRevoked } from '../services/revokedTokenService.js';
import logger from '../utils/logger.js';

export const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) {
    logger.warn('Authentication failed: No token provided');
    return res.sendStatus(401);
  }
  try {
    const payload = jwt.verify(token, process.env.JWT_ACCESS_SECRET);
    if (await isTokenRevoked(payload.jti)) {
      logger.warn('Authentication failed: Token revoked (jti: %s)', payload.jti);
      return res.sendStatus(401);
    }
    req.user = payload;
    logger.info('Authentication successful for user: %s', payload.username);
    next();
  } catch {
    logger.warn('Authentication failed: Invalid token');
    return res.sendStatus(401);
  }
};

export const authorizeRoles =
  (...roles) =>
  (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) {
      logger.warn(
        'Authorization failed: User role %s not in %o',
        req.user ? req.user.role : 'none',
        roles
      );
      return res.sendStatus(403);
    }
    logger.info(
      'Authorization successful for user: %s, role: %s',
      req.user.username,
      req.user.role
    );
    next();
  };
