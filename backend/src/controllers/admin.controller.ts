import { Request, Response, NextFunction } from 'express';
import { z } from 'zod';
import { AdminService } from '@/services/admin.service';
import { sendSuccess }  from '@/utils/response';

const adminService = new AdminService();

export const updateUserSchema = z.object({
  role:     z.enum(['USER', 'ADMIN']).optional(),
  isActive: z.boolean().optional(),
});

export const updateModuleSchema = z.object({
  isActive:       z.boolean().optional(),
  defaultEnabled: z.boolean().optional(),
});

export async function listUsers(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const users = await adminService.listUsers();
    sendSuccess(res, users);
  } catch (err) { next(err); }
}

export async function updateUser(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const user = await adminService.updateUser(req.params.id, req.body);
    sendSuccess(res, user);
  } catch (err) { next(err); }
}

export async function listModules(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const modules = await adminService.listModules();
    sendSuccess(res, modules);
  } catch (err) { next(err); }
}

export async function updateModule(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const mod = await adminService.updateModule(req.params.id, req.body);
    sendSuccess(res, mod);
  } catch (err) { next(err); }
}

export async function getAdminStats(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const stats = await adminService.getGlobalStats();
    sendSuccess(res, stats);
  } catch (err) { next(err); }
}
