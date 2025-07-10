import express from 'express';
import * as authController from '../controllers/authController.js';
import { authLimiter } from '../middlewares/rateLimiter.js';
import { validateRegistration } from '../middlewares/validateRegistration.js';
import { registerLimiter, loginLimiter } from '../middlewares/granularRateLimiter.js';

const router = express.Router();

router.post(
  '/register',
  registerLimiter,
  authLimiter,
  validateRegistration,
  authController.register
);
router.post('/login', loginLimiter, authLimiter, authController.login);
router.post('/refresh', authLimiter, authController.refresh);
router.post('/logout', authLimiter, authController.logout);

export default router;
