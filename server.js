import 'dotenv/config';
import express from 'express';
import authRoutes from './src/routes/authRoutes.js';
import { generalLimiter } from './src/middlewares/rateLimiter.js';
import cors from 'cors';
import { startCleanupJobs, stopCleanupJobs } from './src/utils/cleanupJobs.js';
import logger from './src/utils/logger.js';
import { errorHandler } from './src/middlewares/errorHandler.js';

// --- Environment Variable Validation ---
function validateEnv() {
  const required = [
    'DATABASE_URL',
    'JWT_ACCESS_SECRET',
    'JWT_REFRESH_SECRET',
    'ACCESS_TOKEN_TTL',
    'REFRESH_TOKEN_TTL',
    // 'BCRYPT_COST', // Allow default in test/dev
  ];
  for (const key of required) {
    if (!process.env[key]) {
      throw new Error(`Missing required environment variable: ${key}`);
    }
  }
  if (process.env.JWT_ACCESS_SECRET.length < 32) {
    throw new Error('JWT_ACCESS_SECRET must be at least 32 characters long');
  }
  if (process.env.JWT_REFRESH_SECRET.length < 32) {
    throw new Error('JWT_REFRESH_SECRET must be at least 32 characters long');
  }
  // BCRYPT_COST: allow default in test/dev
  const cost = process.env.BCRYPT_COST
    ? parseInt(process.env.BCRYPT_COST, 10)
    : process.env.NODE_ENV === 'test' || process.env.NODE_ENV === 'development'
      ? 10
      : undefined;
  if (cost === undefined || isNaN(cost) || cost < 10 || cost > 15) {
    throw new Error(
      'BCRYPT_COST must be a number between 10 and 15 (or set NODE_ENV to test/development)'
    );
  }
}
validateEnv();

const app = express();
app.use(express.json());
app.use(generalLimiter);
app.use(
  cors({
    origin: 'http://localhost:5173',
    credentials: true,
  })
);
app.use('/auth', authRoutes);

// Error handler middleware
app.use(errorHandler);

export default app;

const PORT = process.env.PORT || 3000;
let server;
if (process.env.NODE_ENV !== 'test') {
  startCleanupJobs();
  server = app.listen(PORT, () => {
    logger.info(`Server running on port ${PORT}`);
  });
}

// --- DRY graceful shutdown ---
async function shutdown() {
  stopCleanupJobs && stopCleanupJobs();
  if (server) server.close();
  const { disconnectPrisma } = await import('./src/models/index.js');
  await disconnectPrisma();
  process.exit(0);
}
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);

// Provide a default for BCRYPT_COST in test/dev environments
export function getBcryptCost() {
  if (process.env.BCRYPT_COST) return parseInt(process.env.BCRYPT_COST, 10);
  if (process.env.NODE_ENV === 'test' || process.env.NODE_ENV === 'development') return 10;
  throw new Error('Missing required environment variable: BCRYPT_COST');
}
