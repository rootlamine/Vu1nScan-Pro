import { Request, Response, NextFunction } from 'express';
import { prisma } from '@/utils/prisma';
import { sendSuccess } from '@/utils/response';

export async function getDashboardStats(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const userId = req.user!.userId;
    const role   = req.user!.role;

    const userFilter = role === 'ADMIN' ? {} : { userId };

    const now        = new Date();
    const thirtyDaysAgo = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
    const sevenDaysAgo  = new Date(now.getTime() -  7 * 24 * 60 * 60 * 1000);
    const prevWeekStart = new Date(now.getTime() - 14 * 24 * 60 * 60 * 1000);

    // Requêtes parallèles
    const [
      totalScans, totalVulns, activeScans,
      completedScans,
      recentScans, prevWeekScans,
      recentVulns, prevWeekVulns,
      last30DaysScans,
      vulnBySeverity, allVulns,
      moduleResults,
    ] = await Promise.all([
      // KPIs
      prisma.scan.count({ where: userFilter }),
      prisma.vulnerability.count({ where: { scan: userFilter } }),
      prisma.scan.count({ where: { ...userFilter, status: { in: ['PENDING', 'RUNNING'] } } }),
      prisma.scan.count({ where: { ...userFilter, status: 'COMPLETED' } }),
      // Delta semaine actuelle
      prisma.scan.count({ where: { ...userFilter, createdAt: { gte: sevenDaysAgo } } }),
      prisma.scan.count({ where: { ...userFilter, createdAt: { gte: prevWeekStart, lt: sevenDaysAgo } } }),
      prisma.vulnerability.count({ where: { scan: userFilter, createdAt: { gte: sevenDaysAgo } } }),
      prisma.vulnerability.count({ where: { scan: userFilter, createdAt: { gte: prevWeekStart, lt: sevenDaysAgo } } }),
      // Scans 30 jours
      prisma.scan.findMany({
        where:   { ...userFilter, createdAt: { gte: thirtyDaysAgo } },
        select:  { createdAt: true, status: true },
        orderBy: { createdAt: 'asc' },
      }),
      // Vulnérabilités par sévérité
      prisma.vulnerability.groupBy({
        by: ['severity'],
        where: { scan: userFilter },
        _count: { _all: true },
      }),
      // Toutes les vulns (pour catégories)
      prisma.vulnerability.findMany({
        where:   { scan: userFilter },
        select:  { severity: true, cvssScore: true },
        take:    1000,
      }),
      // Résultats modules
      prisma.scanModuleResult.findMany({
        where:   { scan: userFilter },
        select:  { status: true, executionTime: true, module: { select: { name: true, category: true } } },
        take:    500,
      }),
    ]);

    // Histogramme 30 jours (aujourd'hui inclus)
    const dailyMap: Record<string, number> = {};
    for (let i = 29; i >= 0; i--) {
      const d = new Date(now.getTime() - i * 24 * 60 * 60 * 1000);
      const key = d.toISOString().slice(0, 10);
      dailyMap[key] = 0;
    }
    for (const s of last30DaysScans) {
      const key = new Date(s.createdAt).toISOString().slice(0, 10);
      if (key in dailyMap) dailyMap[key]++;
    }
    const scanHistory = Object.entries(dailyMap).sort().map(([date, count]) => ({ date, count }));

    // Répartition sévérités
    const sevMap: Record<string, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    for (const g of vulnBySeverity) sevMap[g.severity] = g._count._all;
    const severityDistribution = Object.entries(sevMap).map(([name, value]) => ({ name, value }));

    // Insights modules
    const modMap: Record<string, { name: string; category: string; done: number; error: number; totalTime: number; count: number }> = {};
    for (const r of moduleResults) {
      const key = r.module.name;
      if (!modMap[key]) modMap[key] = { name: key, category: r.module.category, done: 0, error: 0, totalTime: 0, count: 0 };
      if (r.status === 'DONE')  modMap[key].done++;
      if (r.status === 'ERROR') modMap[key].error++;
      if (r.executionTime) { modMap[key].totalTime += r.executionTime; modMap[key].count++; }
    }
    const moduleInsights = Object.values(modMap)
      .map(m => ({
        name:          m.name,
        category:      m.category,
        detectionRate: m.done + m.error > 0 ? Math.round((m.done / (m.done + m.error)) * 100) : 0,
        avgTime:       m.count > 0 ? Math.round(m.totalTime / m.count) : 0,
        runCount:      m.done + m.error,
      }))
      .sort((a, b) => b.detectionRate - a.detectionRate)
      .slice(0, 10);

    // Delta %
    const delta = (curr: number, prev: number) =>
      prev === 0 ? null : Math.round(((curr - prev) / prev) * 100);

    sendSuccess(res, {
      kpis: {
        totalScans,
        totalVulns,
        activeScans,
        completionRate: totalScans > 0 ? Math.round((completedScans / totalScans) * 100) : 0,
        weeklyScans:    recentScans,
        weeklyVulns:    recentVulns,
        deltaScans:     delta(recentScans, prevWeekScans),
        deltaVulns:     delta(recentVulns, prevWeekVulns),
      },
      scanHistory,
      severityDistribution,
      moduleInsights,
    });
  } catch (err) { next(err); }
}
