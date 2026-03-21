import { Request, Response, NextFunction } from 'express';
import { ReportService } from '@/services/report.service';
import { sendSuccess }   from '@/utils/response';

const reportService = new ReportService();

export async function generateReport(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const report = await reportService.generatePDF(req.params.id, req.user!.userId);
    sendSuccess(res, report, 201);
  } catch (err) { next(err); }
}

export async function listReports(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const reports = await reportService.listReports(req.user!.userId);
    sendSuccess(res, reports);
  } catch (err) { next(err); }
}

export async function downloadReport(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const { filePath } = await reportService.getReportForDownload(req.params.id, req.user!.userId);
    res.download(filePath);
  } catch (err) { next(err); }
}

export async function exportJSON(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const data = await reportService.exportJSON(req.params.id, req.user!.userId);
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename="scan-${req.params.id}.json"`);
    res.json(data);
  } catch (err) { next(err); }
}

export async function exportCSV(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const csv = await reportService.exportCSV(req.params.id, req.user!.userId);
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="scan-${req.params.id}.csv"`);
    res.send('\uFEFF' + csv); // BOM for Excel
  } catch (err) { next(err); }
}
