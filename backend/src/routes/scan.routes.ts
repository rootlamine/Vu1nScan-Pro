import { Router } from 'express';
import { authMiddleware }  from '@/middlewares/auth.middleware';
import { validate }        from '@/middlewares/validate.middleware';
import { scanLimiter }     from '@/middlewares/rate-limit';
import {
  createScan, listScans, getScan, deleteScan, createScanSchema,
} from '@/controllers/scan.controller';
import { listVulnerabilities, getStats } from '@/controllers/vuln.controller';
import { generateReport, exportJSON, exportCSV } from '@/controllers/report.controller';

const router = Router();

router.use(authMiddleware);

router.post  ('/',                    scanLimiter, validate(createScanSchema), createScan);
router.get   ('/',                    listScans);
router.get   ('/:id',                 getScan);
router.delete('/:id',                 deleteScan);
router.get   ('/:id/vulnerabilities', listVulnerabilities);
router.get   ('/:id/stats',           getStats);
router.post  ('/:id/report',          generateReport);
router.get   ('/:id/export/json',     exportJSON);
router.get   ('/:id/export/csv',      exportCSV);

export default router;
