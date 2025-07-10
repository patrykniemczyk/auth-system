import 'dotenv/config';
import express from 'express';
import authRoutes from './src/routes/authRoutes.js';
import { generalLimiter } from './src/middlewares/rateLimiter.js';

const app = express();
app.use(express.json());
app.use(generalLimiter);
app.use('/auth', authRoutes);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
