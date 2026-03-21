import { Router } from 'express';
import { authMiddleware } from '@/middlewares/auth.middleware';
import { listReports, downloadReport } from '@/controllers/report.controller';

const router = Router();

router.use(authMiddleware);

router.get('/',                listReports);
router.get('/:id/download',    downloadReport);

export default router;
