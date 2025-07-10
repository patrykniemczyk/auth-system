import { body, validationResult } from 'express-validator';

export const validateRegistration = [
  body('username')
    .isLength({ min: 3, max: 30 })
    .withMessage('Username must be 3-30 characters long')
    .isAlphanumeric()
    .withMessage('Username must contain only letters and numbers'),
  body('password')
    .isLength({ min: 8 })
    .withMessage('Password must be at least 8 characters long')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$/)
    .withMessage(
      'Password must contain at least one uppercase letter, one lowercase letter, and one number'
    ),
  (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      // Debug: print errors for diagnosis

      console.error('Validation errors:', errors.array());
      if (errors.array().length === 1) {
        return res.status(400).json({ error: errors.array()[0].msg });
      }
      return res.status(400).json({ errors: errors.array() });
    }
    next();
  },
];
