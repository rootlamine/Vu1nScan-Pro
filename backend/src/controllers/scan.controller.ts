import { Request, Response, NextFunction } from 'express';
import { z } from 'zod';
import { ScanService } from '@/services/scan.service';
import { sendSuccess }  from '@/utils/response';

const scanService = new ScanService();

const IP_RE = /^(\d{1,3}\.){3}\d{1,3}(:\d{1,5})?$/;

export const createScanSchema = z.object({
  targetUrl: z.string().transform((val, ctx) => {
    const trimmed = val.trim();
    // Accept plain IP or IP:port — prefix with http://
    if (IP_RE.test(trimmed)) return `http://${trimmed}`;
    // Accept valid URL as-is
    try { new URL(trimmed); return trimmed; } catch { /* fall through */ }
    ctx.addIssue({ code: z.ZodIssueCode.custom, message: 'URL ou adresse IP invalide' });
    return z.NEVER;
  }),
  description: z.string().max(500).optional(),
  depth:       z.enum(['fast', 'normal', 'deep']).default('normal'),
  threads:     z.number().int().min(1).max(20).default(5),
  moduleIds:   z.array(z.string().uuid()).optional(),
});

export async function createScan(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const scan = await scanService.createScan(req.user!.userId, req.body);
    sendSuccess(res, scan, 201);
  } catch (err) { next(err); }
}

export async function listScans(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const page  = Number(req.query.page)  || 1;
    const limit = Number(req.query.limit) || 10;
    const result = await scanService.listScans(req.user!.userId, page, limit);
    sendSuccess(res, result);
  } catch (err) { next(err); }
}

export async function getScan(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const scan = await scanService.getScan(req.params.id, req.user!.userId);
    sendSuccess(res, scan);
  } catch (err) { next(err); }
}

export async function deleteScan(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    await scanService.deleteScan(req.params.id, req.user!.userId);
    sendSuccess(res, { message: 'Scan supprimé' });
  } catch (err) { next(err); }
}
