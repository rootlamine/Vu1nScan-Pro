import { Request, Response, NextFunction } from 'express';
import { z } from 'zod';
import { VulnService } from '@/services/vuln.service';
import { sendSuccess }  from '@/utils/response';

const vulnService = new VulnService();

export const updateVulnSchema = z.object({
  isResolved:      z.boolean().optional(),
  isFalsePositive: z.boolean().optional(),
  notes:           z.string().max(1000).optional(),
});

export async function listVulnerabilities(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const filters = {
      severity: req.query.severity as string | undefined,
      search:   req.query.search   as string | undefined,
    };
    const vulns = await vulnService.listVulnerabilities(
      req.params.id,
      req.user!.userId,
      filters,
    );
    sendSuccess(res, vulns);
  } catch (err) { next(err); }
}

export async function getStats(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const stats = await vulnService.getStats(req.params.id, req.user!.userId);
    sendSuccess(res, stats);
  } catch (err) { next(err); }
}

export async function listAllVulnerabilities(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const filters = {
      severity: req.query.severity as string | undefined,
      search:   req.query.search   as string | undefined,
      limit:    req.query.limit    ? parseInt(req.query.limit as string, 10) : undefined,
      page:     req.query.page     ? parseInt(req.query.page  as string, 10) : undefined,
    };
    const vulns = await vulnService.listAll(req.user!.userId, filters);
    sendSuccess(res, vulns);
  } catch (err) { next(err); }
}

export async function getGlobalStats(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const stats = await vulnService.getGlobalStats(req.user!.userId);
    sendSuccess(res, stats);
  } catch (err) { next(err); }
}

export async function updateVuln(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const vuln = await vulnService.updateVuln(req.params.id, req.user!.userId, req.body);
    sendSuccess(res, vuln);
  } catch (err) { next(err); }
}
