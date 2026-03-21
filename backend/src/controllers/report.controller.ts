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
