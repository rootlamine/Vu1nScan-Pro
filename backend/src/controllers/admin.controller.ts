import { Request, Response, NextFunction } from 'express';
import { z } from 'zod';
import { AdminService } from '@/services/admin.service';
import { sendSuccess }  from '@/utils/response';

const adminService = new AdminService();

export const createUserSchema = z.object({
  username: z.string().min(3).max(30),
  email:    z.string().email(),
  password: z.string().min(8),
  role:     z.enum(['USER', 'ADMIN']).default('USER'),
  isActive: z.boolean().default(true),
});

export const updateUserSchema = z.object({
  role:     z.enum(['USER', 'ADMIN']).optional(),
  isActive: z.boolean().optional(),
});

export const updateModuleSchema = z.object({
  isActive:       z.boolean().optional(),
  defaultEnabled: z.boolean().optional(),
});

export async function createUser(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const user = await adminService.createUser(req.body);
    sendSuccess(res, user, 201);
  } catch (err) { next(err); }
}

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

export const updatePermissionsSchema = z.object({
  maxScansPerDay:         z.number().int().min(0).max(9999).optional(),
  maxScansPerMonth:       z.number().int().min(0).max(9999).optional(),
  maxConcurrentScans:     z.number().int().min(1).max(20).optional(),
  maxTargetsPerScan:      z.number().int().min(1).max(50).optional(),
  maxThreads:             z.number().int().min(1).max(20).optional(),
  maxScanDuration:        z.number().int().min(60).max(7200).optional(),
  maxScanDepth:           z.enum(['fast', 'normal', 'deep']).optional(),
  allowedCategories:      z.array(z.string()).optional(),
  blockedModules:         z.array(z.string()).optional(),
  canUseOffensiveModules: z.boolean().optional(),
  canGenerateReports:     z.boolean().optional(),
  canExportData:          z.boolean().optional(),
  canCreateProfiles:      z.boolean().optional(),
  canScanInternalIPs:     z.boolean().optional(),
  canUseDeepScan:         z.boolean().optional(),
  canScheduleScans:       z.boolean().optional(),
});

export async function getUserPermissions(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const perms = await adminService.getUserPermissions(req.params.id);
    sendSuccess(res, perms);
  } catch (err) { next(err); }
}

export async function updateUserPermissions(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const perms = await adminService.updateUserPermissions(req.params.id, req.body);
    sendSuccess(res, perms);
  } catch (err) { next(err); }
}

export async function resetUserPermissions(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const perms = await adminService.resetUserPermissions(req.params.id);
    sendSuccess(res, perms);
  } catch (err) { next(err); }
}

export async function getUserStats(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const stats = await adminService.getUserStats(req.params.id);
    sendSuccess(res, stats);
  } catch (err) { next(err); }
}
