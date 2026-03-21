import rateLimit from 'express-rate-limit';

export const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10,
  message: { success: false, message: 'Trop de tentatives, réessayez dans 15 minutes' },
  standardHeaders: true,
  legacyHeaders: false,
});

export const scanLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 20,
  message: { success: false, message: 'Trop de requêtes, réessayez dans une minute' },
  standardHeaders: true,
  legacyHeaders: false,
});
