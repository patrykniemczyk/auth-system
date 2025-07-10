import 'dotenv/config';
import express from 'express';
import authRoutes from './src/routes/authRoutes.js';
import { generalLimiter } from './src/middlewares/rateLimiter.js';
import cors from 'cors';
import { startCleanupJobs, stopCleanupJobs } from './src/utils/cleanupJobs.js';
import logger from './src/utils/logger.js';
import { errorHandler } from './src/middlewares/errorHandler.js';

// --- JWT Secret Validation ---
if (!process.env.JWT_ACCESS_SECRET || process.env.JWT_ACCESS_SECRET.length < 32) {
  throw new Error('JWT_ACCESS_SECRET must be at least 32 characters long');
}
if (!process.env.JWT_REFRESH_SECRET || process.env.JWT_REFRESH_SECRET.length < 32) {
  throw new Error('JWT_REFRESH_SECRET must be at least 32 characters long');
}

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

// Graceful shutdown for cleanup jobs and Prisma
process.on('SIGTERM', async () => {
  stopCleanupJobs && stopCleanupJobs();
  if (server) server.close();
  const { disconnectPrisma } = await import('./src/models/index.js');
  await disconnectPrisma();
  process.exit(0);
});
process.on('SIGINT', async () => {
  stopCleanupJobs && stopCleanupJobs();
  if (server) server.close();
  const { disconnectPrisma } = await import('./src/models/index.js');
  await disconnectPrisma();
  process.exit(0);
});
