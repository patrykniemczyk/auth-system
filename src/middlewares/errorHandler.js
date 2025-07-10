import logger from '../utils/logger.js';

/**
 * Express error handler middleware
 * @param {Error} err
 * @param {import('express').Request} req
 * @param {import('express').Response} res
 */
export const errorHandler = (err, req, res) => {
  logger.error('Unhandled error:', err);
  if (err.name === 'PrismaClientKnownRequestError') {
    return res.status(400).json({ error: 'Database operation failed' });
  }
  res.status(500).json({ error: 'Internal server error' });
};
