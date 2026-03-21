import * as fs   from 'fs';
import * as path from 'path';
import puppeteer  from 'puppeteer';
import { Report } from '@prisma/client';
import { ReportRepository } from '@/repositories/report.repository';
import { ScanRepository }   from '@/repositories/scan.repository';
import { VulnRepository }   from '@/repositories/vuln.repository';
import { AppError }         from '@/utils/errors';
import { config }           from '@/utils/config';
import { ReportWithScan }   from '@/domain/interfaces';

const reportRepo = new ReportRepository();
const scanRepo   = new ScanRepository();
const vulnRepo   = new VulnRepository();

const REPORTS_DIR = path.resolve(process.cwd(), config.REPORTS_PATH);

// Créer le dossier reports/ s'il n'existe pas
fs.mkdirSync(REPORTS_DIR, { recursive: true });

function buildHtml(scan: { id: string; targetUrl: string; createdAt: Date | string; completedAt?: Date | string | null }, vulns: { name: string; severity: string; cvssScore?: number | null; endpoint?: string | null; description: string; payload?: string | null; recommendation: string }[]): string {
  const SEV_COLORS: Record<string, string> = {
    CRITICAL: '#FF6B6B',
    HIGH:     '#FFB347',
    MEDIUM:   '#7C6FF7',
    LOW:      '#4ECDC4',
  };
  const SEV_LABELS: Record<string, string> = {
    CRITICAL: 'Critique',
    HIGH:     'Élevé',
    MEDIUM:   'Moyen',
    LOW:      'Faible',
  };

  const vulnRows = vulns.map(v => `
    <div style="margin-bottom:16px;border:1px solid #e5e7eb;border-radius:8px;overflow:hidden;">
      <div style="display:flex;align-items:center;gap:12px;padding:12px 16px;background:#f9fafb;">
        <span style="background:${SEV_COLORS[v.severity]}20;color:${SEV_COLORS[v.severity]};
          border:1px solid ${SEV_COLORS[v.severity]}40;border-radius:999px;padding:2px 10px;
          font-size:11px;font-weight:600;font-family:monospace;">
          ${SEV_LABELS[v.severity] ?? v.severity}
        </span>
        <strong style="font-size:14px;color:#1C1C2E;">${v.name}</strong>
        ${v.cvssScore != null ? `<span style="margin-left:auto;font-family:monospace;font-size:12px;color:#6b7280;">CVSS ${Number(v.cvssScore).toFixed(1)}</span>` : ''}
      </div>
      <div style="padding:12px 16px;font-size:13px;color:#374151;line-height:1.6;">
        ${v.endpoint ? `<p><strong>Endpoint :</strong> <code style="font-size:12px;">${v.endpoint}</code></p>` : ''}
        <p style="margin-top:6px;">${v.description}</p>
        ${v.payload ? `<div style="background:#1C1C2E;border-radius:6px;padding:8px 12px;margin-top:8px;"><code style="color:#4ECDC4;font-size:12px;">${v.payload}</code></div>` : ''}
        <div style="background:#f3f4f6;border-radius:6px;padding:10px 12px;margin-top:10px;border-left:3px solid #7C6FF7;">
          <strong style="color:#7C6FF7;font-size:12px;">Recommandation :</strong>
          <p style="margin-top:4px;color:#374151;">${v.recommendation}</p>
        </div>
      </div>
    </div>
  `).join('');

  const stats = {
    critical: vulns.filter(v => v.severity === 'CRITICAL').length,
    high:     vulns.filter(v => v.severity === 'HIGH').length,
    medium:   vulns.filter(v => v.severity === 'MEDIUM').length,
    low:      vulns.filter(v => v.severity === 'LOW').length,
  };

  return `<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<style>
  body { font-family: 'Segoe UI', Arial, sans-serif; margin: 0; padding: 40px; background: #FFFBF5; color: #1C1C2E; }
  h1   { color: #FF6B6B; font-size: 24px; margin-bottom: 4px; }
  .subtitle { color: #6b7280; font-size: 14px; margin-bottom: 24px; }
  .meta { background: #fff; border: 1px solid #e5e7eb; border-radius: 8px; padding: 16px; margin-bottom: 24px; font-size: 13px; line-height: 1.8; }
  .stats { display: flex; gap: 12px; margin-bottom: 24px; }
  .stat { flex: 1; text-align: center; border-radius: 8px; padding: 12px; border: 1px solid transparent; }
  h2   { font-size: 18px; border-bottom: 2px solid #e5e7eb; padding-bottom: 8px; margin-bottom: 16px; }
  code { font-family: 'Courier New', monospace; }
</style>
</head>
<body>
  <h1>🛡 Rapport VulnScan Pro</h1>
  <p class="subtitle">Rapport de sécurité généré automatiquement</p>

  <div class="meta">
    <strong>Cible analysée :</strong> ${scan.targetUrl}<br>
    <strong>Date du scan :</strong> ${new Date(scan.createdAt).toLocaleString('fr-FR')}<br>
    <strong>Date du rapport :</strong> ${new Date().toLocaleString('fr-FR')}<br>
    <strong>ID du scan :</strong> <code>${scan.id}</code>
  </div>

  <div class="stats">
    <div class="stat" style="background:#FF6B6B10;border-color:#FF6B6B30;color:#FF6B6B;">
      <div style="font-size:28px;font-weight:700;">${stats.critical}</div>
      <div style="font-size:12px;">Critique</div>
    </div>
    <div class="stat" style="background:#FFB34710;border-color:#FFB34730;color:#FFB347;">
      <div style="font-size:28px;font-weight:700;">${stats.high}</div>
      <div style="font-size:12px;">Élevé</div>
    </div>
    <div class="stat" style="background:#7C6FF710;border-color:#7C6FF730;color:#7C6FF7;">
      <div style="font-size:28px;font-weight:700;">${stats.medium}</div>
      <div style="font-size:12px;">Moyen</div>
    </div>
    <div class="stat" style="background:#4ECDC410;border-color:#4ECDC430;color:#4ECDC4;">
      <div style="font-size:28px;font-weight:700;">${stats.low}</div>
      <div style="font-size:12px;">Faible</div>
    </div>
  </div>

  <h2>Vulnérabilités détectées (${vulns.length})</h2>
  ${vulns.length > 0 ? vulnRows : '<p style="color:#9ca3af;">Aucune vulnérabilité détectée.</p>'}
</body>
</html>`;
}

export class ReportService {
  async generatePDF(scanId: string, userId: string): Promise<Report> {
    const scan = await scanRepo.findById(scanId);
    if (!scan) throw new AppError('Scan introuvable', 404);
    if (scan.userId !== userId) throw new AppError('Accès refusé', 403);
    if (scan.status !== 'COMPLETED') throw new AppError('Le scan doit être terminé pour générer un rapport', 400);

    // Retourner le rapport existant si déjà généré
    const existing = await reportRepo.findByScanId(scanId);
    if (existing) return existing;

    const vulns = await vulnRepo.findByScanId(scanId);
    const html  = buildHtml(scan, vulns);

    const filename = `report-${scanId}-${Date.now()}.pdf`;
    const filePath = path.join(REPORTS_DIR, filename);

    const browser = await puppeteer.launch({
      headless: true,
      args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage'],
    });

    try {
      const page = await browser.newPage();
      await page.setContent(html, { waitUntil: 'networkidle0' });
      await page.pdf({ path: filePath, format: 'A4', printBackground: true, margin: { top: '20px', bottom: '20px' } });
    } finally {
      await browser.close();
    }

    const stat     = fs.statSync(filePath);
    const report   = await reportRepo.create({ scanId, filePath, fileSize: stat.size });
    return report;
  }

  async listReports(userId: string): Promise<ReportWithScan[]> {
    return reportRepo.findByUserId(userId);
  }

  async getReportForDownload(reportId: string, userId: string): Promise<{ filePath: string }> {
    const report = await reportRepo.findById(reportId);
    if (!report) throw new AppError('Rapport introuvable', 404);
    if (report.scan.userId !== userId) throw new AppError('Accès refusé', 403);
    if (!fs.existsSync(report.filePath)) throw new AppError('Fichier introuvable sur le serveur', 404);
    return { filePath: report.filePath };
  }
}
