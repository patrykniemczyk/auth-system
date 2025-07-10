import rateLimit from 'express-rate-limit';

// General rate limiter: 100 requests per 15 minutes per IP
/**
 * General rate limiter middleware
 * @type {import('express').RequestHandler}
 */
export const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: 'Too many requests, please try again later.',
  },
});

// Stricter limiter for auth endpoints: 10 requests per 10 minutes per IP
/**
 * Stricter rate limiter for authentication endpoints
 * @type {import('express').RequestHandler}
 */
export const authLimiter = rateLimit({
  windowMs: 10 * 60 * 1000, // 10 minutes
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: 'Too many authentication attempts, please try again later.',
  },
});
