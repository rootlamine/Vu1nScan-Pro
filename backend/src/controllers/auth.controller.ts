import { Request, Response, NextFunction } from 'express';
import { z } from 'zod';
import { AuthService }       from '@/services/auth.service';
import { PermissionService } from '@/services/permission.service';
import { sendSuccess } from '@/utils/response';

const authService = new AuthService();
const permService = new PermissionService();

// ─── Schémas de validation ────────────────────────────────────────────────────

const passwordRule = z
  .string()
  .min(8, 'Minimum 8 caractères')
  .regex(/[A-Z]/, 'Doit contenir une majuscule')
  .regex(/[a-z]/, 'Doit contenir une minuscule')
  .regex(/\d/, 'Doit contenir un chiffre');

export const registerSchema = z.object({
  username: z.string().min(3, 'Minimum 3 caractères').max(30),
  email:    z.string().email('Email invalide'),
  password: passwordRule,
});

export const loginSchema = z.object({
  email:    z.string().email(),
  password: z.string().min(1),
});

export const updateProfileSchema = z.object({
  username: z.string().min(3).max(30).optional(),
  email:    z.string().email().optional(),
}).refine(data => data.username || data.email, {
  message: 'Au moins un champ requis (username ou email)',
});

export const changePasswordSchema = z.object({
  currentPassword: z.string().min(1),
  newPassword:     passwordRule,
});

// ─── Handlers ────────────────────────────────────────────────────────────────

export async function register(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const result = await authService.register(req.body);
    sendSuccess(res, result, 201);
  } catch (err) { next(err); }
}

export async function login(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const result = await authService.login(req.body);
    sendSuccess(res, result);
  } catch (err) { next(err); }
}

export async function me(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const user = await authService.me(req.user!.userId);
    sendSuccess(res, user);
  } catch (err) { next(err); }
}

export async function updateProfile(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const user = await authService.updateProfile(req.user!.userId, req.body);
    sendSuccess(res, user);
  } catch (err) { next(err); }
}

export async function changePassword(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    await authService.changePassword(req.user!.userId, req.body);
    sendSuccess(res, { message: 'Mot de passe modifié avec succès' });
  } catch (err) { next(err); }
}

export async function myLimits(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const [perms, remaining] = await Promise.all([
      permService.getPermissions(req.user!.userId),
      permService.getRemainingScans(req.user!.userId),
    ]);
    sendSuccess(res, { permissions: perms, remaining });
  } catch (err) { next(err); }
}
