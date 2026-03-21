import * as fs   from 'fs';
import * as path from 'path';
import puppeteer  from 'puppeteer';
import { Report, Vulnerability, ScanModuleResult } from '@prisma/client';
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
fs.mkdirSync(REPORTS_DIR, { recursive: true });

// ─── Risk score calculation ───────────────────────────────────────────────────

function calcRiskScore(vulns: Vulnerability[]): number {
  if (!vulns.length) return 0;
  const weights = { CRITICAL: 10, HIGH: 7, MEDIUM: 4, LOW: 1 };
  const raw = vulns.reduce((sum, v) => sum + (weights[v.severity] ?? 0), 0);
  // Normalize to 0–100
  const maxPossible = vulns.length * 10;
  return Math.min(100, Math.round((raw / maxPossible) * 100));
}

function riskLabel(score: number): { label: string; color: string } {
  if (score >= 80) return { label: 'CRITIQUE', color: '#FF6B6B' };
  if (score >= 60) return { label: 'ÉLEVÉ',    color: '#FFB347' };
  if (score >= 40) return { label: 'MOYEN',    color: '#7C6FF7' };
  if (score >= 20) return { label: 'FAIBLE',   color: '#4ECDC4' };
  return { label: 'MINIMAL', color: '#6b7280' };
}

// ─── HTML builder ─────────────────────────────────────────────────────────────

type ScanWithModules = {
  id: string; targetUrl: string; description?: string | null;
  status: string; depth: string; threads: number;
  createdAt: Date | string; startedAt?: Date | string | null; completedAt?: Date | string | null;
  moduleResults?: (ScanModuleResult & { module: { name: string; slug: string; category: string } })[];
};

const SEV_COLORS: Record<string, string> = {
  CRITICAL: '#FF6B6B', HIGH: '#FFB347', MEDIUM: '#7C6FF7', LOW: '#4ECDC4',
};
const SEV_LABELS: Record<string, string> = {
  CRITICAL: 'Critique', HIGH: 'Élevé', MEDIUM: 'Moyen', LOW: 'Faible',
};

function buildHtml(scan: ScanWithModules, vulns: Vulnerability[]): string {
  const stats = {
    critical: vulns.filter(v => v.severity === 'CRITICAL').length,
    high:     vulns.filter(v => v.severity === 'HIGH').length,
    medium:   vulns.filter(v => v.severity === 'MEDIUM').length,
    low:      vulns.filter(v => v.severity === 'LOW').length,
  };
  const riskScore  = calcRiskScore(vulns);
  const { label: rLabel, color: rColor } = riskLabel(riskScore);
  const genDate = new Date().toLocaleString('fr-FR');
  const scanDate = scan.createdAt ? new Date(scan.createdAt).toLocaleString('fr-FR') : '—';
  const completedDate = scan.completedAt ? new Date(scan.completedAt).toLocaleString('fr-FR') : '—';
  const duration = scan.startedAt && scan.completedAt
    ? Math.round((new Date(scan.completedAt).getTime() - new Date(scan.startedAt).getTime()) / 1000)
    : null;

  // Priority sorting for remediation: CRITICAL first
  const sortedVulns = [...vulns].sort((a, b) => {
    const order = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
    return (order[a.severity] ?? 4) - (order[b.severity] ?? 4);
  });

  const top3 = sortedVulns.slice(0, 3);

  // Module results
  const moduleResults = scan.moduleResults ?? [];
  const doneModules   = moduleResults.filter(r => r.status === 'DONE');
  const errorModules  = moduleResults.filter(r => r.status === 'ERROR');

  const vulnCards = sortedVulns.map((v, i) => `
    <div style="margin-bottom:16px;border:1px solid #e5e7eb;border-radius:10px;overflow:hidden;page-break-inside:avoid;">
      <div style="display:flex;align-items:center;gap:12px;padding:12px 16px;background:#f9fafb;border-bottom:1px solid #e5e7eb;">
        <span style="min-width:24px;height:24px;border-radius:50%;background:${SEV_COLORS[v.severity]};color:#fff;font-size:11px;font-weight:700;display:flex;align-items:center;justify-content:center;">${i + 1}</span>
        <span style="background:${SEV_COLORS[v.severity]}20;color:${SEV_COLORS[v.severity]};border:1px solid ${SEV_COLORS[v.severity]}40;border-radius:999px;padding:2px 10px;font-size:11px;font-weight:600;">
          ${SEV_LABELS[v.severity] ?? v.severity}
        </span>
        <strong style="font-size:14px;color:#1C1C2E;flex:1;">${v.name}</strong>
        ${v.cvssScore != null ? `<span style="font-family:monospace;font-size:12px;background:#1C1C2E;color:#4ECDC4;padding:2px 8px;border-radius:4px;">CVSS ${Number(v.cvssScore).toFixed(1)}</span>` : ''}
        ${v.cveId ? `<span style="font-family:monospace;font-size:11px;color:#6b7280;">${v.cveId}</span>` : ''}
        ${v.cweId ? `<span style="font-family:monospace;font-size:11px;color:#6b7280;">${v.cweId}</span>` : ''}
      </div>
      <div style="padding:14px 16px;font-size:13px;color:#374151;line-height:1.7;">
        ${v.endpoint ? `<p style="margin:0 0 8px;"><strong>Endpoint :</strong> <code style="background:#f3f4f6;padding:1px 6px;border-radius:4px;font-size:12px;">${v.endpoint}</code>${v.parameter ? ` — Paramètre : <code style="background:#f3f4f6;padding:1px 6px;border-radius:4px;font-size:12px;">${v.parameter}</code>` : ''}</p>` : ''}
        ${v.cvssVector ? `<p style="margin:0 0 8px;"><strong>Vecteur CVSS :</strong> <code style="font-size:11px;color:#6b7280;">${v.cvssVector}</code></p>` : ''}
        <p style="margin:0 0 10px;">${v.description}</p>
        ${v.impact ? `<div style="background:#FFF7ED;border-left:3px solid #FFB347;border-radius:4px;padding:8px 12px;margin-bottom:10px;"><strong style="color:#B45309;font-size:12px;">Impact :</strong><p style="margin:4px 0 0;color:#374151;">${v.impact}</p></div>` : ''}
        ${v.payload ? `<div style="background:#1C1C2E;border-radius:6px;padding:8px 12px;margin-bottom:10px;"><code style="color:#4ECDC4;font-size:12px;">${v.payload}</code></div>` : ''}
        ${v.evidence ? `<div style="background:#f0fdf4;border-left:3px solid #4ECDC4;border-radius:4px;padding:8px 12px;margin-bottom:10px;"><strong style="color:#065f46;font-size:12px;">Preuve :</strong><code style="display:block;margin-top:4px;font-size:11px;color:#374151;">${v.evidence}</code></div>` : ''}
        <div style="background:#f5f3ff;border-radius:6px;padding:10px 12px;margin-bottom:10px;border-left:3px solid #7C6FF7;">
          <strong style="color:#7C6FF7;font-size:12px;">Recommandation :</strong>
          <p style="margin:4px 0 0;color:#374151;">${v.recommendation}</p>
        </div>
        ${v.references && v.references.length > 0 ? `
        <div style="background:#F0EEFF;border-radius:6px;padding:10px 12px;border-left:3px solid #7C6FF7;">
          <strong style="color:#7C6FF7;font-size:12px;">Références :</strong>
          <ul style="margin:6px 0 0;padding-left:16px;">
            ${v.references.map(r => `<li style="margin:3px 0;"><a href="${r}" style="color:#7C6FF7;font-size:11px;word-break:break-all;">${r}</a></li>`).join('')}
          </ul>
        </div>` : ''}
      </div>
    </div>
  `).join('');

  // Gauge SVG for risk score
  const gaugeAngle = Math.round((riskScore / 100) * 180);
  const gaugeX = 100 + 80 * Math.cos(((180 - gaugeAngle) * Math.PI) / 180);
  const gaugeY = 90  - 80 * Math.sin(((180 - gaugeAngle) * Math.PI) / 180);

  // Remediation plan
  const p1 = sortedVulns.filter(v => v.severity === 'CRITICAL' || v.severity === 'HIGH');
  const p2 = sortedVulns.filter(v => v.severity === 'MEDIUM');
  const p3 = sortedVulns.filter(v => v.severity === 'LOW');

  const remPlan = (items: Vulnerability[], priority: string, color: string, delay: string) =>
    items.length === 0 ? '' : `
    <div style="margin-bottom:14px;border:1px solid ${color}30;border-radius:8px;overflow:hidden;">
      <div style="background:${color}15;padding:10px 14px;border-left:4px solid ${color};display:flex;justify-content:space-between;align-items:center;">
        <strong style="color:${color};">${priority}</strong>
        <span style="font-size:12px;color:#6b7280;">Délai recommandé : ${delay}</span>
      </div>
      <ul style="margin:8px 0;padding-left:20px;">
        ${items.map(v => `<li style="margin:4px 0;font-size:13px;color:#374151;">${v.name}${v.endpoint ? ` — <code style="font-size:11px;">${v.endpoint}</code>` : ''}</li>`).join('')}
      </ul>
    </div>`;

  return `<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<style>
  @page { margin: 0; }
  * { box-sizing: border-box; }
  body { font-family: 'Segoe UI', Arial, sans-serif; margin: 0; padding: 0; background: #FFFBF5; color: #1C1C2E; }
  .page { padding: 40px 50px; }
  .cover { background: linear-gradient(135deg, #1C1C2E 0%, #2d2d44 100%); color: white; padding: 60px 50px; min-height: 100vh; display: flex; flex-direction: column; }
  h1, h2, h3 { margin: 0; }
  code { font-family: 'Courier New', monospace; }
  .page-break { page-break-before: always; }
  .section-title { font-size: 20px; color: #1C1C2E; border-bottom: 3px solid #FF6B6B; padding-bottom: 8px; margin-bottom: 20px; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  table th { background: #1C1C2E; color: #fff; padding: 8px 12px; text-align: left; }
  table td { padding: 8px 12px; border-bottom: 1px solid #e5e7eb; }
  table tr:hover td { background: #f9fafb; }
</style>
</head>
<body>

<!-- ═══ PAGE 1 : COUVERTURE ═══════════════════════════════════════════════ -->
<div class="cover">
  <div style="flex:1;">
    <div style="display:flex;align-items:center;gap:12px;margin-bottom:60px;">
      <div style="width:48px;height:48px;background:#FF6B6B;border-radius:12px;display:flex;align-items:center;justify-content:center;font-size:24px;">🛡</div>
      <div>
        <div style="font-size:22px;font-weight:700;color:#fff;">VulnScan Pro</div>
        <div style="font-size:12px;color:#9ca3af;">Plateforme d'analyse de sécurité</div>
      </div>
    </div>

    <h1 style="font-size:36px;font-weight:700;color:#fff;margin-bottom:12px;">Rapport de Sécurité</h1>
    <p style="color:#9ca3af;font-size:16px;margin-bottom:48px;">Analyse de vulnérabilités — Rapport confidentiel</p>

    <div style="background:rgba(255,255,255,0.08);border-radius:12px;padding:24px;margin-bottom:40px;">
      <div style="font-size:13px;color:#9ca3af;margin-bottom:4px;">Cible analysée</div>
      <div style="font-size:18px;color:#FF6B6B;font-family:monospace;word-break:break-all;">${scan.targetUrl}</div>
    </div>

    <!-- Jauge de risque -->
    <div style="text-align:center;margin-bottom:40px;">
      <svg width="200" height="110" viewBox="0 0 200 110">
        <path d="M20 90 A80 80 0 0 1 180 90" fill="none" stroke="#374151" stroke-width="18" stroke-linecap="round"/>
        <path d="M20 90 A80 80 0 0 1 180 90" fill="none" stroke="${rColor}" stroke-width="18" stroke-linecap="round"
          stroke-dasharray="${gaugeAngle * 2.51} 452" stroke-dashoffset="0"/>
        <line x1="100" y1="90" x2="${gaugeX.toFixed(1)}" y2="${gaugeY.toFixed(1)}" stroke="#fff" stroke-width="3" stroke-linecap="round"/>
        <circle cx="100" cy="90" r="6" fill="#fff"/>
        <text x="100" y="110" text-anchor="middle" fill="${rColor}" font-size="28" font-weight="700" font-family="Arial">${riskScore}</text>
      </svg>
      <div style="font-size:24px;font-weight:700;color:${rColor};margin-top:8px;">${rLabel}</div>
      <div style="font-size:13px;color:#9ca3af;">Score de risque global</div>
    </div>

    <!-- Stats rapides -->
    <div style="display:flex;gap:12px;justify-content:center;">
      ${[['CRITIQUE', stats.critical, '#FF6B6B'], ['ÉLEVÉ', stats.high, '#FFB347'], ['MOYEN', stats.medium, '#7C6FF7'], ['FAIBLE', stats.low, '#4ECDC4']].map(([l, n, c]) => `
      <div style="flex:1;text-align:center;background:${c}20;border:1px solid ${c}40;border-radius:8px;padding:12px;">
        <div style="font-size:28px;font-weight:700;color:${c};">${n}</div>
        <div style="font-size:11px;color:#9ca3af;">${l}</div>
      </div>`).join('')}
    </div>
  </div>

  <div style="border-top:1px solid rgba(255,255,255,0.1);margin-top:40px;padding-top:20px;display:flex;justify-content:space-between;font-size:12px;color:#9ca3af;">
    <span>ID scan : <code style="color:#7C6FF7;">${scan.id}</code></span>
    <span>Généré le ${genDate}</span>
  </div>
</div>

<!-- ═══ PAGE 2 : RÉSUMÉ EXÉCUTIF ════════════════════════════════════════ -->
<div class="page page-break">
  <div class="section-title">Résumé Exécutif</div>

  <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:24px;">
    <div style="background:#fff;border:1px solid #e5e7eb;border-radius:8px;padding:16px;">
      <div style="font-size:12px;color:#6b7280;margin-bottom:8px;">INFORMATIONS DU SCAN</div>
      <table style="font-size:13px;">
        <tr><td style="color:#6b7280;padding:4px 0;border:none;width:40%;">Cible</td><td style="padding:4px 0;border:none;word-break:break-all;"><code style="font-size:11px;">${scan.targetUrl}</code></td></tr>
        <tr><td style="color:#6b7280;padding:4px 0;border:none;">Profondeur</td><td style="padding:4px 0;border:none;text-transform:capitalize;">${scan.depth}</td></tr>
        <tr><td style="color:#6b7280;padding:4px 0;border:none;">Threads</td><td style="padding:4px 0;border:none;">${scan.threads}</td></tr>
        <tr><td style="color:#6b7280;padding:4px 0;border:none;">Lancé le</td><td style="padding:4px 0;border:none;">${scanDate}</td></tr>
        <tr><td style="color:#6b7280;padding:4px 0;border:none;">Terminé le</td><td style="padding:4px 0;border:none;">${completedDate}</td></tr>
        ${duration ? `<tr><td style="color:#6b7280;padding:4px 0;border:none;">Durée</td><td style="padding:4px 0;border:none;">${duration}s</td></tr>` : ''}
      </table>
    </div>
    <div style="background:#fff;border:1px solid #e5e7eb;border-radius:8px;padding:16px;">
      <div style="font-size:12px;color:#6b7280;margin-bottom:8px;">MODULES EXÉCUTÉS</div>
      <div style="font-size:28px;font-weight:700;color:#1C1C2E;">${moduleResults.length}</div>
      <div style="font-size:12px;color:#6b7280;margin-bottom:12px;">modules analysés</div>
      <div style="display:flex;gap:8px;">
        <div style="flex:1;text-align:center;background:#dcfce7;border-radius:6px;padding:8px;">
          <div style="font-size:18px;font-weight:700;color:#16a34a;">${doneModules.length}</div>
          <div style="font-size:11px;color:#16a34a;">Succès</div>
        </div>
        <div style="flex:1;text-align:center;background:#fee2e2;border-radius:6px;padding:8px;">
          <div style="font-size:18px;font-weight:700;color:#dc2626;">${errorModules.length}</div>
          <div style="font-size:11px;color:#dc2626;">Erreurs</div>
        </div>
      </div>
    </div>
  </div>

  ${top3.length > 0 ? `
  <div style="margin-bottom:24px;">
    <div style="font-size:15px;font-weight:600;color:#1C1C2E;margin-bottom:12px;">Top 3 Vulnérabilités Critiques</div>
    ${top3.map((v, i) => `
    <div style="display:flex;align-items:center;gap:12px;padding:12px;background:#fff;border:1px solid ${SEV_COLORS[v.severity]}30;border-radius:8px;margin-bottom:8px;border-left:4px solid ${SEV_COLORS[v.severity]};">
      <span style="font-size:20px;font-weight:700;color:${SEV_COLORS[v.severity]};min-width:24px;">${i + 1}</span>
      <div style="flex:1;">
        <div style="font-weight:600;font-size:14px;">${v.name}</div>
        ${v.endpoint ? `<div style="font-size:12px;color:#6b7280;margin-top:2px;"><code>${v.endpoint}</code></div>` : ''}
      </div>
      ${v.cvssScore != null ? `<span style="font-family:monospace;font-size:13px;font-weight:700;color:${SEV_COLORS[v.severity]};">CVSS ${Number(v.cvssScore).toFixed(1)}</span>` : ''}
    </div>`).join('')}
  </div>` : ''}

  <div style="background:#f5f3ff;border-radius:8px;padding:16px;border-left:4px solid #7C6FF7;">
    <div style="font-weight:600;color:#7C6FF7;margin-bottom:8px;">Recommandations Prioritaires</div>
    <ol style="margin:0;padding-left:16px;font-size:13px;line-height:1.8;">
      ${p1.slice(0, 5).map(v => `<li>${v.recommendation.split('.')[0]}.</li>`).join('')}
      ${p2.slice(0, 3).map(v => `<li>${v.recommendation.split('.')[0]}.</li>`).join('')}
    </ol>
  </div>
</div>

<!-- ═══ PAGE 3 : ANALYSE TECHNIQUE ══════════════════════════════════════ -->
<div class="page page-break">
  <div class="section-title">Analyse Technique — Résultats par Module</div>

  ${moduleResults.length > 0 ? `
  <table>
    <thead>
      <tr>
        <th>Module</th>
        <th>Catégorie</th>
        <th>Statut</th>
        <th>Durée</th>
        <th>Vulnérabilités</th>
      </tr>
    </thead>
    <tbody>
      ${moduleResults.map(r => {
        const modVulns = vulns.filter(() => false); // filled statically
        const statusColor = r.status === 'DONE' ? '#16a34a' : r.status === 'ERROR' ? '#dc2626' : '#6b7280';
        return `<tr>
          <td><strong>${r.module.name}</strong></td>
          <td><code style="font-size:11px;color:#6b7280;">${r.module.category}</code></td>
          <td><span style="color:${statusColor};font-weight:600;font-size:12px;">${r.status}</span></td>
          <td>${r.executionTime ? `${(r.executionTime / 1000).toFixed(1)}s` : '—'}</td>
          <td>—</td>
        </tr>`;
      }).join('')}
    </tbody>
  </table>` : '<p style="color:#9ca3af;">Aucune donnée de module disponible.</p>'}
</div>

<!-- ═══ PAGE 4 : VULNÉRABILITÉS ═════════════════════════════════════════ -->
<div class="page page-break">
  <div class="section-title">Vulnérabilités Détectées (${vulns.length})</div>
  ${vulns.length > 0 ? vulnCards : '<p style="color:#9ca3af;font-size:14px;">Aucune vulnérabilité détectée lors de ce scan.</p>'}
</div>

<!-- ═══ PAGE 5 : PLAN DE REMÉDIATION ════════════════════════════════════ -->
<div class="page page-break">
  <div class="section-title">Plan de Remédiation</div>

  ${remPlan(p1, 'P1 — Priorité Critique/Haute (immédiat)', '#FF6B6B', '< 48h')}
  ${remPlan(p2, 'P2 — Priorité Moyenne (court terme)', '#FFB347', '< 2 semaines')}
  ${remPlan(p3, 'P3 — Priorité Faible (planifiable)', '#4ECDC4', '< 1 mois')}

  ${vulns.length === 0 ? '<p style="color:#9ca3af;">Aucune action requise — aucune vulnérabilité détectée.</p>' : ''}

  <!-- Glossaire -->
  <div style="margin-top:32px;">
    <div style="font-size:16px;font-weight:600;color:#1C1C2E;margin-bottom:12px;">Glossaire</div>
    <table>
      <tr><th width="150">Terme</th><th>Définition</th></tr>
      <tr><td>CVSS</td><td>Common Vulnerability Scoring System — score de 0 à 10 mesurant la gravité d'une vulnérabilité.</td></tr>
      <tr><td>CVE</td><td>Common Vulnerabilities and Exposures — identifiant public d'une vulnérabilité connue.</td></tr>
      <tr><td>CWE</td><td>Common Weakness Enumeration — classification des types de faiblesses logicielles.</td></tr>
      <tr><td>OWASP</td><td>Open Web Application Security Project — référentiel de bonnes pratiques de sécurité web.</td></tr>
      <tr><td>XSS</td><td>Cross-Site Scripting — injection de code JavaScript malveillant dans une page web.</td></tr>
      <tr><td>SQLi</td><td>SQL Injection — manipulation des requêtes SQL via des entrées non filtrées.</td></tr>
      <tr><td>LFI/RFI</td><td>Local/Remote File Inclusion — inclusion de fichiers non autorisés côté serveur.</td></tr>
      <tr><td>SSRF</td><td>Server-Side Request Forgery — requêtes non autorisées émises par le serveur.</td></tr>
    </table>
  </div>

  <!-- Avertissement légal -->
  <div style="margin-top:24px;padding:14px;background:#fef2f2;border-radius:8px;border-left:4px solid #FF6B6B;">
    <strong style="color:#dc2626;font-size:12px;">Avertissement légal</strong>
    <p style="margin:6px 0 0;font-size:12px;color:#374151;">Ce rapport est CONFIDENTIEL. Il est destiné exclusivement aux personnes autorisées de l'organisation ciblée.
    Toute reproduction ou divulgation à des tiers non autorisés est interdite. L'analyse a été réalisée dans un cadre légal et avec autorisation explicite du propriétaire de la cible.</p>
  </div>

  <div style="margin-top:24px;text-align:center;font-size:11px;color:#9ca3af;border-top:1px solid #e5e7eb;padding-top:16px;">
    VulnScan Pro — Rapport généré le ${genDate} — Score de risque : ${riskScore}/100 (${rLabel})
  </div>
</div>

</body>
</html>`;
}

// ─── CSV builder ──────────────────────────────────────────────────────────────

function buildCsv(vulns: Vulnerability[]): string {
  const headers = ['Nom', 'Sévérité', 'Score CVSS', 'Vecteur CVSS', 'CVE', 'CWE', 'Endpoint', 'Paramètre', 'Description', 'Payload', 'Recommandation', 'Résolu', 'Faux Positif', 'Notes'];
  const esc = (s: string | null | undefined) => `"${(s ?? '').replace(/"/g, '""')}"`;
  const rows = vulns.map(v => [
    esc(v.name), esc(v.severity), v.cvssScore?.toString() ?? '', esc(v.cvssVector), esc(v.cveId), esc(v.cweId),
    esc(v.endpoint), esc(v.parameter), esc(v.description), esc(v.payload),
    esc(v.recommendation), v.isResolved ? 'Oui' : 'Non', v.isFalsePositive ? 'Oui' : 'Non', esc(v.notes),
  ].join(','));
  return [headers.join(','), ...rows].join('\n');
}

// ─── Service ──────────────────────────────────────────────────────────────────

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
    const html  = buildHtml(scan as ScanWithModules, vulns);

    const filename = `report-${scanId}-${Date.now()}.pdf`;
    const filePath = path.join(REPORTS_DIR, filename);

    const browser = await puppeteer.launch({
      headless: true,
      args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage'],
    });

    try {
      const page = await browser.newPage();
      await page.setContent(html, { waitUntil: 'networkidle0' });
      await page.pdf({
        path: filePath, format: 'A4', printBackground: true,
        margin: { top: '0', bottom: '0', left: '0', right: '0' },
      });
    } finally {
      await browser.close();
    }

    const stat   = fs.statSync(filePath);
    const report = await reportRepo.create({ scanId, filePath, fileSize: stat.size });
    return report;
  }

  async exportJSON(scanId: string, userId: string): Promise<object> {
    const scan = await scanRepo.findById(scanId);
    if (!scan) throw new AppError('Scan introuvable', 404);
    if (scan.userId !== userId) throw new AppError('Accès refusé', 403);

    const vulns = await vulnRepo.findByScanId(scanId);
    const riskScore = calcRiskScore(vulns);
    const { label } = riskLabel(riskScore);

    return {
      reportMeta: { generatedAt: new Date().toISOString(), tool: 'VulnScan Pro', version: '1.0.0' },
      scan: {
        id: scan.id, targetUrl: scan.targetUrl, description: scan.description,
        status: scan.status, depth: scan.depth, threads: scan.threads,
        createdAt: scan.createdAt, startedAt: scan.startedAt, completedAt: scan.completedAt,
      },
      riskScore: { score: riskScore, label },
      summary: {
        total:    vulns.length,
        critical: vulns.filter(v => v.severity === 'CRITICAL').length,
        high:     vulns.filter(v => v.severity === 'HIGH').length,
        medium:   vulns.filter(v => v.severity === 'MEDIUM').length,
        low:      vulns.filter(v => v.severity === 'LOW').length,
      },
      vulnerabilities: vulns,
    };
  }

  async exportCSV(scanId: string, userId: string): Promise<string> {
    const scan = await scanRepo.findById(scanId);
    if (!scan) throw new AppError('Scan introuvable', 404);
    if (scan.userId !== userId) throw new AppError('Accès refusé', 403);

    const vulns = await vulnRepo.findByScanId(scanId);
    return buildCsv(vulns);
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
