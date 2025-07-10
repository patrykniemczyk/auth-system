import logger from '../utils/logger.js';

export const errorHandler = (err, req, res) => {
  logger.error('Unhandled error:', err);
  if (err.name === 'PrismaClientKnownRequestError') {
    return res.status(400).json({ error: 'Database operation failed' });
  }
  res.status(500).json({ error: 'Internal server error' });
};
