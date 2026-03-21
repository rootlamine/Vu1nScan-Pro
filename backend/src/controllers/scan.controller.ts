import { Request, Response, NextFunction } from 'express';
import { z } from 'zod';
import { ScanService } from '@/services/scan.service';
import { sendSuccess }  from '@/utils/response';

const scanService = new ScanService();

export const createScanSchema = z.object({
  targetUrl:   z.string().url('URL invalide'),
  description: z.string().max(500).optional(),
  depth:       z.enum(['fast', 'normal', 'deep']).default('normal'),
  threads:     z.number().int().min(1).max(20).default(5),
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
