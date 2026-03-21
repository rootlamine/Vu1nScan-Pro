import { Router } from 'express';
import { authLimiter } from '@/middlewares/rate-limit';
import { authMiddleware } from '@/middlewares/auth.middleware';
import { validate } from '@/middlewares/validate.middleware';
import {
  register, login, me, updateProfile, changePassword, myLimits,
  registerSchema, loginSchema, updateProfileSchema, changePasswordSchema,
} from '@/controllers/auth.controller';

const router = Router();

router.post('/register', authLimiter, validate(registerSchema), register);
router.post('/login',    authLimiter, validate(loginSchema),    login);
router.get('/me',        authMiddleware, me);
router.patch('/profile', authMiddleware, validate(updateProfileSchema), updateProfile);
router.patch('/password', authMiddleware, validate(changePasswordSchema), changePassword);
router.get('/me/limits',  authMiddleware, myLimits);

export default router;
