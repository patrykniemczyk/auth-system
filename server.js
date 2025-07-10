import 'dotenv/config';
import express from 'express';
import authRoutes from './src/routes/authRoutes.js';
import { generalLimiter } from './src/middlewares/rateLimiter.js';
import cors from 'cors';
import { startCleanupJobs } from './cleanupJobs.js';
import logger from './src/utils/logger.js';

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

export default app;

const PORT = process.env.PORT || 3000;
if (process.env.NODE_ENV !== 'test') {
  startCleanupJobs();
  app.listen(PORT, () => {
    logger.info(`Server running on port ${PORT}`);
  });
}
