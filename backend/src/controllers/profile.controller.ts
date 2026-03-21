import { Request, Response, NextFunction } from 'express';
import { z } from 'zod';
import { ProfileService } from '@/services/profile.service';
import { sendSuccess }    from '@/utils/response';

const profileService = new ProfileService();

export const createProfileSchema = z.object({
  name:        z.string().min(1).max(100),
  description: z.string().max(500).optional(),
  modules:     z.array(z.string()).min(1),
  isDefault:   z.boolean().optional(),
});

export const updateProfileSchema = z.object({
  name:        z.string().min(1).max(100).optional(),
  description: z.string().max(500).optional(),
  modules:     z.array(z.string()).min(1).optional(),
  isDefault:   z.boolean().optional(),
});

export async function listProfiles(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const profiles = await profileService.listProfiles(req.user!.userId);
    sendSuccess(res, profiles);
  } catch (err) { next(err); }
}

export async function createProfile(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const profile = await profileService.createProfile(req.user!.userId, req.body);
    sendSuccess(res, profile, 201);
  } catch (err) { next(err); }
}

export async function updateProfile(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const profile = await profileService.updateProfile(req.params.id, req.user!.userId, req.body);
    sendSuccess(res, profile);
  } catch (err) { next(err); }
}

export async function deleteProfile(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    await profileService.deleteProfile(req.params.id, req.user!.userId);
    sendSuccess(res, { message: 'Profil supprimé' });
  } catch (err) { next(err); }
}

export async function applyProfile(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const result = await profileService.applyProfile(req.params.id, req.user!.userId);
    sendSuccess(res, result);
  } catch (err) { next(err); }
}
