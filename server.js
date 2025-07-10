import 'dotenv/config';
import express from 'express';
import authRoutes from './src/routes/authRoutes.js';
import { generalLimiter } from './src/middlewares/rateLimiter.js';
import cors from 'cors';

const app = express();
app.use(express.json());
app.use(generalLimiter);
app.use(
  cors({
    origin: 'http://localhost:3000',
    credentials: true,
  })
);
app.use('/auth', authRoutes);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
