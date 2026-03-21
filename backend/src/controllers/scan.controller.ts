import { Request, Response, NextFunction } from 'express';
import { z } from 'zod';
import { ScanService } from '@/services/scan.service';
import { sendSuccess }  from '@/utils/response';
import { prisma }       from '@/utils/prisma';
import { AppError }     from '@/utils/errors';

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
    const scan = await scanService.createScan(req.user!.userId, req.user!.role, req.body);
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

export async function getScanLive(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const userId = req.user!.userId;
    const { id } = req.params;

    const [scan, vulns] = await Promise.all([
      prisma.scan.findUnique({
        where:   { id },
        include: {
          moduleResults: {
            include:  { module: true },
            orderBy:  { createdAt: 'asc' },
          },
        },
      }),
      prisma.vulnerability.findMany({
        where:   { scanId: id },
        select:  { id: true, name: true, severity: true, cvssScore: true, endpoint: true, createdAt: true },
        orderBy: { createdAt: 'asc' },
      }),
    ]);

    if (!scan) throw new AppError('Scan introuvable', 404);
    if (scan.userId !== userId) throw new AppError('Accès refusé', 403);

    const total     = scan.moduleResults.length;
    const completed = scan.moduleResults.filter(r => r.status === 'DONE').length;
    const errors    = scan.moduleResults.filter(r => r.status === 'ERROR').length;
    const running   = scan.moduleResults.filter(r => r.status === 'RUNNING').length;
    const pending   = scan.moduleResults.filter(r => r.status === 'PENDING').length;

    const sevCounts = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const v of vulns) {
      if (v.severity === 'CRITICAL')     sevCounts.critical++;
      else if (v.severity === 'HIGH')   sevCounts.high++;
      else if (v.severity === 'MEDIUM') sevCounts.medium++;
      else if (v.severity === 'LOW')    sevCounts.low++;
    }

    sendSuccess(res, {
      scan: {
        id: scan.id, status: scan.status, targetUrl: scan.targetUrl,
        depth: scan.depth, threads: scan.threads,
        startedAt: scan.startedAt, completedAt: scan.completedAt, createdAt: scan.createdAt,
      },
      moduleResults: scan.moduleResults.map(r => ({
        id:                r.id,
        moduleId:          r.moduleId,
        moduleName:        r.module.name,
        moduleSlug:        r.module.slug,
        moduleDescription: r.module.description,
        moduleCategory:    r.module.category,
        status:            r.status,
        executionTime:     r.executionTime,
      })),
      vulnerabilities: vulns,
      stats: {
        total, completed, errors, running, pending,
        progressPercent: total > 0 ? Math.round(((completed + errors) / total) * 100) : 0,
        vulnerabilitiesFound: sevCounts,
      },
    });
  } catch (err) { next(err); }
}
