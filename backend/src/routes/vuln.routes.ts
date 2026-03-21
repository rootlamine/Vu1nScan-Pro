import { Router } from 'express';
import { authMiddleware } from '@/middlewares/auth.middleware';
import { listAllVulnerabilities, getGlobalStats } from '@/controllers/vuln.controller';

const router = Router();

router.use(authMiddleware);

router.get('/stats', getGlobalStats);
router.get('/',      listAllVulnerabilities);

export default router;
