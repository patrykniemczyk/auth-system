import rateLimit from 'express-rate-limit';

/**
 * Rate limiter for registration endpoint: 3 requests per hour per IP
 */
export const registerLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 3,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: 'Too many registration attempts, please try again later.',
  },
});

/**
 * Rate limiter for login endpoint: 5 requests per 10 minutes per IP
 */
export const loginLimiter = rateLimit({
  windowMs: 10 * 60 * 1000, // 10 minutes
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: 'Too many login attempts, please try again later.',
  },
});
